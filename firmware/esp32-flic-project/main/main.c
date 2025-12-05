#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_netif.h"
#include "esp_eth.h"
#include "esp_http_client.h"
#include "esp_http_server.h"
#include "nvs_flash.h"
#include "cJSON.h"
#include "esp_mac.h"
#include "mdns.h"
#include "driver/gpio.h"
#include "esp_random.h"
#include "lwip/ip4_addr.h"
#include "driver/spi_master.h"
#include "version.h"
#include "freertos/semphr.h"
#include "esp_ota_ops.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"

#include "../components/flic2/include/flic2_esp32.h"

static const char *TAG = "ESP32_FLIC";

#define SERVER_PORT "5000"
#define MAX_HTTP_OUTPUT_BUFFER 2048
#define W5500_SPI_CLOCK_MHZ 12
#define HEARTBEAT_INTERVAL_MS 30000
#define STATUS_LED_GPIO 2
#define PAIRING_TIMEOUT_MS 60000
static esp_timer_handle_t pairing_timeout_timer = NULL;

#define W5500_SPI_HOST          SPI2_HOST
#define W5500_SCLK_GPIO         13
#define W5500_MOSI_GPIO         11
#define W5500_MISO_GPIO         12
#define W5500_CS_GPIO           14
#define W5500_INT_GPIO          10
#define W5500_RST_GPIO          9

static esp_netif_t *eth_netif = NULL;
static bool ethernet_connected = false;
static bool flash_mode_requested = false;
static bool server_discovered = false;
bool pairing_mode_enabled = false;
static char device_mac[18];
static char server_ip_address[32] = "";
static TaskHandle_t heartbeat_task_handle = NULL;

#define BUTTON_EVENT_TIMEOUT_MS 5000

typedef struct {
    char button_mac[18];
    char event_type[16];
    int battery_mv;
    int64_t timestamp_ms;
} queued_button_event_t;

#define MAX_QUEUED_EVENTS 100
static queued_button_event_t queued_events[MAX_QUEUED_EVENTS];
static int queued_events_head = 0;
static int queued_events_tail = 0;
static SemaphoreHandle_t queued_events_mutex = NULL;

static bool ble_controller_initialized = false;
static bool flic2_library_initialized = false;
static bool flic_scanning_active = false;
static char flic_init_error[256] = "";
static int flic_buttons_paired = 0;
static char last_flic_event[128] = "No events yet";

static eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
static eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();

static bool ota_in_progress = false;
static char ota_status[256] = "No OTA in progress";

static esp_err_t ota_update_handler(httpd_req_t *req);
static esp_err_t perform_ota_update(const char* firmware_url, const char* expected_version);
static void ota_task(void* pvParameters);


typedef struct {
    char endpoint[64];
    char json_data[8192];
} http_post_params_t;

typedef struct {
    char firmware_url[256];
    char expected_version[32];
} ota_params_t;

static int64_t get_current_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000LL + (int64_t)tv.tv_usec / 1000LL;
}

static bool is_queue_full(void) {
    return ((queued_events_head + 1) % MAX_QUEUED_EVENTS) == queued_events_tail;
}

static bool is_queue_empty(void) {
    return queued_events_head == queued_events_tail;
}

static bool enqueue_button_event(const char* button_mac, const char* event_type, int battery_mv) {
    if (xSemaphoreTake(queued_events_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        ESP_LOGW(TAG, "Failed to acquire queue mutex for enqueue");
        return false;
    }

    if (is_queue_full()) {
        xSemaphoreGive(queued_events_mutex);
        ESP_LOGW(TAG, "Event queue is full, dropping event");
        return false;
    }

    queued_button_event_t* event = &queued_events[queued_events_head];
    strncpy(event->button_mac, button_mac, sizeof(event->button_mac) - 1);
    event->button_mac[sizeof(event->button_mac) - 1] = '\0';
    strncpy(event->event_type, event_type, sizeof(event->event_type) - 1);
    event->event_type[sizeof(event->event_type) - 1] = '\0';
    event->battery_mv = battery_mv;
    event->timestamp_ms = get_current_time_ms();

    queued_events_head = (queued_events_head + 1) % MAX_QUEUED_EVENTS;

    xSemaphoreGive(queued_events_mutex);
    return true;
}

static bool dequeue_button_event(char* button_mac, char* event_type, int* battery_mv) {
    if (xSemaphoreTake(queued_events_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        ESP_LOGW(TAG, "Failed to acquire queue mutex for dequeue");
        return false;
    }

    int64_t current_time = get_current_time_ms();

    while (!is_queue_empty()) {
        queued_button_event_t* event = &queued_events[queued_events_tail];
        int64_t age_ms = current_time - event->timestamp_ms;

        if (age_ms > BUTTON_EVENT_TIMEOUT_MS) {
            ESP_LOGW(TAG, "Dropping expired event: %s (%s), age: %lld ms",
                     event->button_mac, event->event_type, age_ms);
            queued_events_tail = (queued_events_tail + 1) % MAX_QUEUED_EVENTS;
            continue;
        }

        strcpy(button_mac, event->button_mac);
        strcpy(event_type, event->event_type);
        *battery_mv = event->battery_mv;
        queued_events_tail = (queued_events_tail + 1) % MAX_QUEUED_EVENTS;

        xSemaphoreGive(queued_events_mutex);
        return true;
    }

    xSemaphoreGive(queued_events_mutex);
    return false;
}

static void init_status_led(void) {
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << STATUS_LED_GPIO),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&io_conf);
    gpio_set_level(STATUS_LED_GPIO, 0);
}

static void set_status_led(bool on) {
    gpio_set_level(STATUS_LED_GPIO, on ? 1 : 0);
}

static void blink_status_led(int times, int delay_ms) {
    for (int i = 0; i < times; i++) {
        set_status_led(true);
        vTaskDelay(pdMS_TO_TICKS(delay_ms));
        set_status_led(false);
        if (i < times - 1) {
            vTaskDelay(pdMS_TO_TICKS(delay_ms));
        }
    }
}

static bool test_server_connection(const char* ip) {
    esp_http_client_config_t config = {
        .url = "temp",
        .timeout_ms = 3000,
        .method = HTTP_METHOD_GET,
    };

    char url[128];
    snprintf(url, sizeof(url), "http://%s:5000/health", ip);
    config.url = url;

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        ESP_LOGW(TAG, "Failed to create HTTP client for %s", ip);
        return false;
    }

    esp_err_t err = esp_http_client_perform(client);
    int status_code = 0;

    if (err == ESP_OK) {
        status_code = esp_http_client_get_status_code(client);
    }

    esp_http_client_cleanup(client);

    bool success = (err == ESP_OK && status_code == 200);
    if (success) {
        ESP_LOGI(TAG, "Server health check successful at %s", ip);
    } else {
        ESP_LOGD(TAG, "Server health check failed at %s (err: %s, status: %d)",
                ip, esp_err_to_name(err), status_code);
    }

    return success;
}

static esp_err_t discover_server_via_mdns(void) {
    ESP_LOGI(TAG, "Starting mDNS discovery for Server...");

    esp_err_t err = mdns_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "mDNS init failed: %s", esp_err_to_name(err));
        return err;
    }

    mdns_hostname_set("esp32s3-flic");
    mdns_instance_name_set("ESP32-S3 Flic Gateway");

    mdns_result_t *results = NULL;
    err = mdns_query_ptr("_http", "_tcp", 5000, 20, &results);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "mDNS query failed: %s", esp_err_to_name(err));
        mdns_free();
        return err;
    }

    if (!results) {
        ESP_LOGI(TAG, "No mDNS services found");
        mdns_free();
        return ESP_FAIL;
    }

    mdns_result_t *r = results;
    bool found = false;

    while (r && !found) {
        if (r->instance_name) {
            ESP_LOGI(TAG, "Found mDNS service: %s", r->instance_name);

            if (strstr(r->instance_name, "flic-ble-server")) {

                if (r->addr) {
                    sprintf(server_ip_address, IPSTR, IP2STR(&r->addr->addr.u_addr.ip4));
                    ESP_LOGI(TAG, "Testing server candidate at: %s:%d", server_ip_address, r->port);

                    if (test_server_connection(server_ip_address)) {
                        server_discovered = true;
                        found = true;
                        ESP_LOGI(TAG, "Found server via mDNS: %s", server_ip_address);
                    }
                }
            }
        }
        r = r->next;
    }

    mdns_query_results_free(results);
    mdns_free();

    return found ? ESP_OK : ESP_FAIL;
}

static esp_err_t discover_server_fallback(void) {
    ESP_LOGI(TAG, "Starting server discovery...");

    esp_netif_ip_info_t ip_info;
    esp_err_t ret = esp_netif_get_ip_info(eth_netif, &ip_info);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get network info: %s", esp_err_to_name(ret));
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "ESP32 Network Status:");
    ESP_LOGI(TAG, "  IP: " IPSTR, IP2STR(&ip_info.ip));
    ESP_LOGI(TAG, "  Gateway: " IPSTR, IP2STR(&ip_info.gw));
    ESP_LOGI(TAG, "  Netmask: " IPSTR, IP2STR(&ip_info.netmask));

    if (ip_info.gw.addr == 0) {
        ESP_LOGE(TAG, "No gateway configured - cannot discover server");
        return ESP_FAIL;
    }

    char base_ip[16];
    sprintf(base_ip, "%d.%d.%d.",
            esp_ip4_addr1_16(&ip_info.ip),
            esp_ip4_addr2_16(&ip_info.ip),
            esp_ip4_addr3_16(&ip_info.ip));

    ESP_LOGI(TAG, "Scanning network %sX for server...", base_ip);

    uint8_t common_server_endings[] = {
        100, 101, 102, 50, 51, 52, 10, 11, 12, 200,
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
        1, 254, 253, 252
    };

    for (int i = 0; i < sizeof(common_server_endings); i++) {
        snprintf(server_ip_address, sizeof(server_ip_address), "%s%d", base_ip, common_server_endings[i]);

        ESP_LOGI(TAG, "Trying server IP: %s", server_ip_address);

        if (test_server_connection(server_ip_address)) {
            server_discovered = true;
            ESP_LOGI(TAG, "Found server at: %s", server_ip_address);
            return ESP_OK;
        }

        vTaskDelay(pdMS_TO_TICKS(200));
    }

    ESP_LOGE(TAG, "Server not found in network %sX", base_ip);
    ESP_LOGI(TAG, "Is the server service running? Try: curl http://<server-ip>:5000/health");
    return ESP_FAIL;
}

static void http_post_task(void* pvParameters) {
    http_post_params_t* params = (http_post_params_t*)pvParameters;

    if (!server_discovered) {
        ESP_LOGW(TAG, "Server not discovered yet, cannot send data");
        free(params);
        vTaskDelete(NULL);
        return;
    }

    char url[128];
    snprintf(url, sizeof(url), "http://%s:%s%s", server_ip_address, SERVER_PORT, params->endpoint);

    esp_http_client_config_t config = {
        .url = url,
        .method = HTTP_METHOD_POST,
        .timeout_ms = 3000,
        .buffer_size = 16384,
        .buffer_size_tx = 16384,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, params->json_data, strlen(params->json_data));

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        int status_code = esp_http_client_get_status_code(client);
        if (status_code == 200) {
            blink_status_led(1, 100);
        } else {
            ESP_LOGW(TAG, "HTTP POST returned status %d", status_code);
        }
    } else {
        ESP_LOGE(TAG, "HTTP POST failed: %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
    free(params);
    vTaskDelete(NULL);
}

static esp_err_t post_to_server_async(const char* endpoint, const char* json_data) {
    http_post_params_t* params = malloc(sizeof(http_post_params_t));
    if (!params) {
        return ESP_ERR_NO_MEM;
    }

    strncpy(params->endpoint, endpoint, sizeof(params->endpoint) - 1);
    strncpy(params->json_data, json_data, sizeof(params->json_data) - 1);
    params->endpoint[sizeof(params->endpoint) - 1] = '\0';
    params->json_data[sizeof(params->json_data) - 1] = '\0';

    BaseType_t result = xTaskCreate(http_post_task, "http_post", 8192, params, 5, NULL);
    return (result == pdPASS) ? ESP_OK : ESP_FAIL;
}

static void send_heartbeat(void) {
    if (!server_discovered) return;

    esp_netif_ip_info_t ip_info;
    esp_netif_get_ip_info(eth_netif, &ip_info);

    cJSON *json = cJSON_CreateObject();
    cJSON *type = cJSON_CreateString("heartbeat");
    cJSON *mac_addr = cJSON_CreateString(device_mac);
    char ip_str[16];
    esp_ip4addr_ntoa(&ip_info.ip, ip_str, sizeof(ip_str));
    cJSON *ip_addr = cJSON_CreateString(ip_str);
    cJSON *fw_version = cJSON_CreateString(FIRMWARE_VERSION);
    cJSON *pairing_mode = cJSON_CreateBool(pairing_mode_enabled);
    cJSON *flic_scanning = cJSON_CreateBool(flic_scanning_active);

    cJSON *paired_button_macs = flic2_esp32_get_paired_buttons_json();

    cJSON_AddItemToObject(json, "type", type);
    cJSON_AddItemToObject(json, "mac_address", mac_addr);
    cJSON_AddItemToObject(json, "ip_address", ip_addr);
    cJSON_AddItemToObject(json, "firmware_version", fw_version);
    cJSON_AddItemToObject(json, "pairing_mode", pairing_mode);
    cJSON_AddItemToObject(json, "flic_scanning", flic_scanning);
    cJSON_AddItemToObject(json, "paired_button_macs", paired_button_macs);

    char *json_string = cJSON_Print(json);
    post_to_server_async("/heartbeat", json_string);

    free(json_string);
    cJSON_Delete(json);
}

static void send_device_discovery(void) {
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_ETH);
    snprintf(device_mac, sizeof(device_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    esp_netif_ip_info_t ip_info;
    esp_netif_get_ip_info(eth_netif, &ip_info);

    cJSON *json = cJSON_CreateObject();
    cJSON *type = cJSON_CreateString("device_discovery");
    cJSON *mac_addr = cJSON_CreateString(device_mac);
    char ip_str[16];
    esp_ip4addr_ntoa(&ip_info.ip, ip_str, sizeof(ip_str));
    cJSON *ip_addr = cJSON_CreateString(ip_str);
    cJSON *fw_version = cJSON_CreateString(FIRMWARE_VERSION);

    cJSON_AddItemToObject(json, "type", type);
    cJSON_AddItemToObject(json, "mac_address", mac_addr);
    cJSON_AddItemToObject(json, "ip_address", ip_addr);
    cJSON_AddItemToObject(json, "firmware_version", fw_version);

    char *json_string = cJSON_Print(json);
    post_to_server_async("/device-discovery", json_string);

    free(json_string);
    cJSON_Delete(json);
}

static int calculate_battery_percentage(int millivolts) {
    const int BATTERY_MAX = 3000;
    const int BATTERY_MIN = 2400;

    if (millivolts >= BATTERY_MAX) return 100;
    if (millivolts <= BATTERY_MIN) return 0;

    return ((millivolts - BATTERY_MIN) * 100) / (BATTERY_MAX - BATTERY_MIN);
}

static void send_button_event(const char* button_mac, const char* event_type, int battery_mv) {
    int battery_pct = calculate_battery_percentage(battery_mv);

    cJSON *json = cJSON_CreateObject();
    cJSON *type = cJSON_CreateString("button_event");
    cJSON *evt_type = cJSON_CreateString(event_type);
    cJSON *btn_mac = cJSON_CreateString(button_mac);
    cJSON *esp32_mac = cJSON_CreateString(device_mac);
    cJSON *bat_pct = cJSON_CreateNumber(battery_pct);
    cJSON *bat_mv = cJSON_CreateNumber(battery_mv);

    cJSON_AddItemToObject(json, "type", type);
    cJSON_AddItemToObject(json, "event_type", evt_type);
    cJSON_AddItemToObject(json, "button_mac", btn_mac);
    cJSON_AddItemToObject(json, "esp32_mac", esp32_mac);
    cJSON_AddItemToObject(json, "battery_percentage", bat_pct);
    cJSON_AddItemToObject(json, "battery_voltage_mv", bat_mv);

    char *json_string = cJSON_Print(json);
    ESP_LOGI(TAG, "Sending button event: %s", json_string);

    post_to_server_async("/button-press", json_string);

    free(json_string);
    cJSON_Delete(json);

    blink_status_led(2, 100);
}

static void button_event_processor_task(void* pvParameters) {
    char button_mac[18];
    char event_type[16];
    int battery_mv;

    while (1) {
        if (server_discovered && dequeue_button_event(button_mac, event_type, &battery_mv)) {
            send_button_event(button_mac, event_type, battery_mv);
        }

        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

static void send_flic_pairing_result(const char* button_mac, const char* result, const char* name) {
    cJSON *json = cJSON_CreateObject();
    cJSON *type = cJSON_CreateString("flic_pairing_result");
    cJSON *mac = cJSON_CreateString(button_mac);
    cJSON *res = cJSON_CreateString(result);
    cJSON *esp32_mac = cJSON_CreateString(device_mac);
    if (name) {
        cJSON *button_name = cJSON_CreateString(name);
        cJSON_AddItemToObject(json, "button_name", button_name);
    }

    cJSON_AddItemToObject(json, "type", type);
    cJSON_AddItemToObject(json, "button_mac", mac);
    cJSON_AddItemToObject(json, "result", res);
    cJSON_AddItemToObject(json, "esp32_mac", esp32_mac);

    char *json_string = cJSON_Print(json);
    ESP_LOGI(TAG, "Sending pairing result: %s", json_string);

    post_to_server_async("/flic-pairing", json_string);

    free(json_string);
    cJSON_Delete(json);

    blink_status_led(3, 100);
}

static void pairing_timeout_callback(void* arg) {
    ESP_LOGI(TAG, "Pairing mode timeout - disabling pairing mode");
    pairing_mode_enabled = false;

    blink_status_led(1, 200);
}

static void init_pairing_timeout_timer(void) {
    esp_timer_create_args_t timer_args = {
        .callback = pairing_timeout_callback,
        .arg = NULL,
        .name = "pairing_timeout"
    };
    esp_timer_create(&timer_args, &pairing_timeout_timer);
}


static esp_err_t enable_pairing_handler(httpd_req_t *req) {
    ESP_LOGI(TAG, "Pairing mode enabled via HTTP request");
    pairing_mode_enabled = true;

    if (!flic_scanning_active) {
        flic2_esp32_start_scan();
        flic_scanning_active = true;
    }

    if (pairing_timeout_timer) {
        esp_timer_stop(pairing_timeout_timer);
        esp_timer_start_once(pairing_timeout_timer, PAIRING_TIMEOUT_MS * 1000);
        ESP_LOGI(TAG, "Pairing mode will auto-disable in %d seconds", PAIRING_TIMEOUT_MS / 1000);
    }

    blink_status_led(5, 50);

    httpd_resp_set_status(req, "200 OK");
    httpd_resp_set_type(req, "application/json");

    char response[128];
    snprintf(response, sizeof(response),
             "{\"status\":\"pairing_enabled\",\"timeout_seconds\":%d}",
             PAIRING_TIMEOUT_MS / 1000);
    httpd_resp_send(req, response, -1);

    return ESP_OK;
}


static esp_err_t disable_pairing_handler(httpd_req_t *req) {
    ESP_LOGI(TAG, "Pairing mode disabled via HTTP request");
    pairing_mode_enabled = false;

    if (pairing_timeout_timer) {
        esp_timer_stop(pairing_timeout_timer);
    }

    httpd_resp_set_status(req, "200 OK");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, "{\"status\":\"pairing_disabled\"}", -1);

    return ESP_OK;
}

static esp_err_t unpair_button_handler(httpd_req_t *req) {
    char buf[128];
    int total_len = req->content_len;
    int cur_len = 0;
    int received = 0;

    if (total_len >= sizeof(buf)) {
        httpd_resp_send_err(req, HTTPD_414_URI_TOO_LONG, "Content too long");
        return ESP_FAIL;
    }

    while (cur_len < total_len) {
        received = httpd_req_recv(req, buf + cur_len, total_len);
        if (received <= 0) {
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to receive data");
            return ESP_FAIL;
        }
        cur_len += received;
    }
    buf[total_len] = '\0';

    cJSON *json = cJSON_Parse(buf);
    if (json == NULL) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *button_mac = cJSON_GetObjectItem(json, "button_mac");
    if (!cJSON_IsString(button_mac)) {
        cJSON_Delete(json);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing button_mac");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Unpairing button: %s", button_mac->valuestring);

    esp_err_t ret = flic2_esp32_unpair_button(button_mac->valuestring);

    cJSON_Delete(json);

    if (ret == ESP_OK) {
        httpd_resp_set_status(req, "200 OK");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"status\":\"unpaired\"}", -1);

        blink_status_led(4, 100);
    } else if (ret == ESP_ERR_NOT_FOUND) {
        httpd_resp_set_status(req, "404 Not Found");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"status\":\"error\",\"message\":\"Button not found\"}", -1);
    } else {
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"status\":\"error\",\"message\":\"Unpair failed\"}", -1);
    }

    return ESP_OK;
}

static esp_err_t flash_mode_handler(httpd_req_t *req) {
    ESP_LOGI(TAG, "Flash mode requested - rebooting to bootloader");
    flash_mode_requested = true;

    httpd_resp_set_status(req, "200 OK");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, "{\"status\":\"entering_flash_mode\"}", -1);

    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();

    return ESP_OK;
}

static esp_err_t ota_http_event_handler(esp_http_client_event_t *evt) {
    switch (evt->event_id) {
        case HTTP_EVENT_ERROR:
            ESP_LOGD(TAG, "HTTP_EVENT_ERROR");
            break;
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
            break;
        case HTTP_EVENT_HEADER_SENT:
            ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
            break;
        case HTTP_EVENT_ON_HEADER:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
            break;
        case HTTP_EVENT_ON_DATA:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
            break;
        case HTTP_EVENT_ON_FINISH:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH");
            break;
        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGD(TAG, "HTTP_EVENT_DISCONNECTED");
            break;
        default:
            break;
    }
    return ESP_OK;
}

static void ota_task(void* pvParameters) {
    ota_params_t* params = (ota_params_t*)pvParameters;
    esp_err_t ret = perform_ota_update(params->firmware_url, params->expected_version);

    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "OTA update successful - restarting");
        strcpy(ota_status, "OTA completed successfully - restarting");
        vTaskDelay(pdMS_TO_TICKS(2000));
        esp_restart();
    } else {
        ESP_LOGE(TAG, "OTA update failed: %s", esp_err_to_name(ret));
        snprintf(ota_status, sizeof(ota_status), "OTA failed: %s", esp_err_to_name(ret));
        ota_in_progress = false;
    }

    free(params);
    vTaskDelete(NULL);
}

static esp_err_t perform_ota_update(const char* firmware_url, const char* expected_version) {
    ESP_LOGI(TAG, "Starting OTA update from: %s", firmware_url);
    ESP_LOGI(TAG, "Expected version: %s", expected_version);

    esp_http_client_config_t config = {
        .url = firmware_url,
        .event_handler = ota_http_event_handler,
        .timeout_ms = 30000,
        .keep_alive_enable = true,
        .is_async = false,
        .transport_type = HTTP_TRANSPORT_OVER_TCP,
    };

    esp_https_ota_config_t ota_config = {
        .http_config = &config,
        .bulk_flash_erase = true,
        .partial_http_download = true,
    };

    esp_err_t ret = esp_https_ota(&ota_config);

    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "OTA Succeed, Rebooting...");
        return ESP_OK;
    } else {
        ESP_LOGE(TAG, "Firmware upgrade failed: %s", esp_err_to_name(ret));
        return ret;
    }
}

static esp_err_t ota_update_handler(httpd_req_t *req) {
    if (ota_in_progress) {
        ESP_LOGW(TAG, "OTA already in progress, ignoring new request");
        httpd_resp_set_status(req, "409 Conflict");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"status\":\"error\",\"message\":\"OTA update already in progress\"}", -1);
        return ESP_OK;
    }

    char buf[512];
    int total_len = req->content_len;
    int cur_len = 0;
    int received = 0;

    if (total_len >= sizeof(buf)) {
        httpd_resp_send_err(req, HTTPD_414_URI_TOO_LONG, "Content too long");
        return ESP_FAIL;
    }

    while (cur_len < total_len) {
        received = httpd_req_recv(req, buf + cur_len, total_len);
        if (received <= 0) {
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to receive data");
            return ESP_FAIL;
        }
        cur_len += received;
    }
    buf[total_len] = '\0';

    cJSON *json = cJSON_Parse(buf);
    if (json == NULL) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *firmware_url_json = cJSON_GetObjectItem(json, "firmware_url");
    cJSON *expected_version_json = cJSON_GetObjectItem(json, "expected_version");

    if (!cJSON_IsString(firmware_url_json) || !cJSON_IsString(expected_version_json)) {
        cJSON_Delete(json);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing firmware_url or expected_version");
        return ESP_FAIL;
    }

    ota_params_t* params = malloc(sizeof(ota_params_t));
    if (!params) {
        cJSON_Delete(json);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Memory allocation failed");
        return ESP_FAIL;
    }

    strncpy(params->firmware_url, firmware_url_json->valuestring, sizeof(params->firmware_url) - 1);
    params->firmware_url[sizeof(params->firmware_url) - 1] = '\0';

    strncpy(params->expected_version, expected_version_json->valuestring, sizeof(params->expected_version) - 1);
    params->expected_version[sizeof(params->expected_version) - 1] = '\0';

    cJSON_Delete(json);

    ESP_LOGI(TAG, "OTA update requested: %s -> %s", params->firmware_url, params->expected_version);

    ota_in_progress = true;
    strcpy(ota_status, "OTA update starting...");

    BaseType_t task_created = xTaskCreate(
        ota_task,
        "ota_task",
        8192,
        params,
        5,
        NULL
    );

    if (task_created != pdPASS) {
        free(params);
        ota_in_progress = false;
        strcpy(ota_status, "Failed to create OTA task");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to create OTA task");
        return ESP_FAIL;
    }

    httpd_resp_set_status(req, "200 OK");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, "{\"status\":\"ota_started\"}", -1);

    return ESP_OK;
}


static esp_err_t status_handler(httpd_req_t *req) {
    cJSON *json = cJSON_CreateObject();
    cJSON *status = cJSON_CreateString(flash_mode_requested ? "flash_mode" : "normal");
    cJSON *ethernet = cJSON_CreateBool(ethernet_connected);
    cJSON *server_found = cJSON_CreateBool(server_discovered);
    cJSON *pairing = cJSON_CreateBool(pairing_mode_enabled);
    cJSON *fw_version = cJSON_CreateString(FIRMWARE_VERSION);
    cJSON *mac = cJSON_CreateString(device_mac);

    cJSON *ble_status = cJSON_CreateBool(ble_controller_initialized);
    cJSON *flic_lib_status = cJSON_CreateBool(flic2_library_initialized);
    cJSON *flic_scan_status = cJSON_CreateBool(flic_scanning_active);
    cJSON *flic_error = cJSON_CreateString(flic_init_error);
    cJSON *flic_paired = cJSON_CreateNumber(flic_buttons_paired);
    cJSON *flic_last_event = cJSON_CreateString(last_flic_event);

    cJSON *ota_active = cJSON_CreateBool(ota_in_progress);
    cJSON *ota_status_json = cJSON_CreateString(ota_status);

    cJSON_AddItemToObject(json, "status", status);
    cJSON_AddItemToObject(json, "ethernet_connected", ethernet);
    cJSON_AddItemToObject(json, "server_discovered", server_found);
    cJSON_AddItemToObject(json, "pairing_mode", pairing);
    cJSON_AddItemToObject(json, "firmware_version", fw_version);
    cJSON_AddItemToObject(json, "device_mac", mac);
    cJSON_AddItemToObject(json, "ble_controller_ready", ble_status);
    cJSON_AddItemToObject(json, "flic2_library_ready", flic_lib_status);
    cJSON_AddItemToObject(json, "flic_scanning", flic_scan_status);
    cJSON_AddItemToObject(json, "flic_init_error", flic_error);
    cJSON_AddItemToObject(json, "flic_buttons_paired", flic_paired);
    cJSON_AddItemToObject(json, "last_flic_event", flic_last_event);
    cJSON_AddItemToObject(json, "ota_in_progress", ota_active);
    cJSON_AddItemToObject(json, "ota_status", ota_status_json);

    char *json_string = cJSON_Print(json);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json_string, -1);

    free(json_string);
    cJSON_Delete(json);

    return ESP_OK;
}

static void start_http_server(void) {
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;

    ESP_LOGI(TAG, "Starting HTTP server on port: %d", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_uri_t flash_mode_uri = {
            .uri = "/flash-mode",
            .method = HTTP_POST,
            .handler = flash_mode_handler,
        };

        httpd_uri_t unpair_button_uri = {
            .uri = "/unpair-button",
            .method = HTTP_POST,
            .handler = unpair_button_handler,
        };

        httpd_uri_t status_uri = {
            .uri = "/status",
            .method = HTTP_GET,
            .handler = status_handler,
        };

        httpd_uri_t enable_pairing_uri = {
            .uri = "/enable-pairing",
            .method = HTTP_POST,
            .handler = enable_pairing_handler,
        };

        httpd_uri_t disable_pairing_uri = {
            .uri = "/disable-pairing",
            .method = HTTP_POST,
            .handler = disable_pairing_handler,
        };

        httpd_uri_t ota_update_uri = {
            .uri = "/ota-update",
            .method = HTTP_POST,
            .handler = ota_update_handler,
        };

        httpd_register_uri_handler(server, &flash_mode_uri);
        httpd_register_uri_handler(server, &status_uri);
        httpd_register_uri_handler(server, &enable_pairing_uri);
        httpd_register_uri_handler(server, &disable_pairing_uri);
        httpd_register_uri_handler(server, &ota_update_uri);
        httpd_register_uri_handler(server, &unpair_button_uri);

        ESP_LOGI(TAG, "HTTP server started successfully");
        ESP_LOGI(TAG, "OTA endpoint available at: /ota-update");
    }
}

static void eth_event_handler(void *arg, esp_event_base_t event_base,
                              int32_t event_id, void *event_data) {
    if (event_base == ETH_EVENT && event_id == ETHERNET_EVENT_CONNECTED) {
        ESP_LOGI(TAG, "Ethernet Link Up");
        set_status_led(true);

    } else if (event_base == ETH_EVENT && event_id == ETHERNET_EVENT_DISCONNECTED) {
        ESP_LOGI(TAG, "Ethernet Link Down");
        ethernet_connected = false;
        server_discovered = false;
        set_status_led(false);

    } else if (event_base == IP_EVENT && event_id == IP_EVENT_ETH_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *) event_data;
        ESP_LOGI(TAG, "=== Network Configuration ===");
        ESP_LOGI(TAG, "IP: " IPSTR, IP2STR(&event->ip_info.ip));
        ESP_LOGI(TAG, "Netmask: " IPSTR, IP2STR(&event->ip_info.netmask));
        ESP_LOGI(TAG, "Gateway: " IPSTR, IP2STR(&event->ip_info.gw));

        if (event->ip_info.gw.addr != 0) {
            ESP_LOGI(TAG, "Got valid network configuration!");
            ethernet_connected = true;
            blink_status_led(3, 200);
        } else {
            ESP_LOGW(TAG, "Got IP but no gateway - network may not work properly");
            ethernet_connected = true;
        }
    }
}

static void network_monitor_task(void *pvParameters) {
    int link_check_count = 0;

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(5000));

        if (ethernet_connected) {
            link_check_count = 0;
            continue;
        }

        link_check_count++;

        if (link_check_count % 6 == 0) {
            ESP_LOGW(TAG, "Network still not connected after %d seconds", link_check_count * 5);

            esp_netif_ip_info_t ip_info;
            if (esp_netif_get_ip_info(eth_netif, &ip_info) == ESP_OK) {
                ESP_LOGI(TAG, "Current network state:");
                ESP_LOGI(TAG, "  IP: " IPSTR, IP2STR(&ip_info.ip));
                ESP_LOGI(TAG, "  Gateway: " IPSTR, IP2STR(&ip_info.gw));
                ESP_LOGI(TAG, "  Netmask: " IPSTR, IP2STR(&ip_info.netmask));
            }
        }

        if (link_check_count >= 24) {
            ESP_LOGW(TAG, "Network connection failed for 2 minutes, restarting DHCP...");
            esp_netif_dhcpc_stop(eth_netif);
            vTaskDelay(pdMS_TO_TICKS(2000));
            esp_netif_dhcpc_start(eth_netif);
            link_check_count = 0;
        }
    }
}


static void ethernet_init(void)
{
    ESP_LOGI(TAG, "Initializing Ethernet");

    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, &eth_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &eth_event_handler, NULL));

    spi_bus_config_t buscfg = {
        .mosi_io_num = W5500_MOSI_GPIO,
        .miso_io_num = W5500_MISO_GPIO,
        .sclk_io_num = W5500_SCLK_GPIO,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
    };
    ESP_ERROR_CHECK(spi_bus_initialize(W5500_SPI_HOST, &buscfg, SPI_DMA_CH_AUTO));

    spi_device_interface_config_t devcfg = {
        .command_bits = 16,
        .address_bits = 8,
        .mode = 0,
        .clock_speed_hz = W5500_SPI_CLOCK_MHZ * 1000 * 1000,
        .spics_io_num = W5500_CS_GPIO,
        .queue_size = 20
    };

    eth_w5500_config_t w5500_config = ETH_W5500_DEFAULT_CONFIG(W5500_SPI_HOST, &devcfg);
    w5500_config.int_gpio_num = W5500_INT_GPIO;

    uint8_t eth_mac[6];
    esp_read_mac(eth_mac, ESP_MAC_ETH);
    ESP_LOGI(TAG, "Using Ethernet MAC: %02x:%02x:%02x:%02x:%02x:%02x",
             eth_mac[0], eth_mac[1], eth_mac[2], eth_mac[3], eth_mac[4], eth_mac[5]);

    esp_eth_mac_t *mac = esp_eth_mac_new_w5500(&w5500_config, &mac_config);
    esp_eth_phy_t *phy = esp_eth_phy_new_w5500(&phy_config);

    esp_eth_config_t config = ETH_DEFAULT_CONFIG(mac, phy);
    esp_eth_handle_t eth_handle = NULL;
    ESP_ERROR_CHECK(esp_eth_driver_install(&config, &eth_handle));

    ESP_ERROR_CHECK(esp_eth_ioctl(eth_handle, ETH_CMD_S_MAC_ADDR, eth_mac));
    ESP_LOGI(TAG, "MAC address set successfully");

    ESP_ERROR_CHECK(esp_netif_attach(eth_netif, esp_eth_new_netif_glue(eth_handle)));
    ESP_ERROR_CHECK(esp_eth_start(eth_handle));

    ESP_LOGI(TAG, "Ethernet initialized - DHCP will start automatically when link is up");
}

void flic_button_event_callback(const char* button_mac, int event_type, int battery_mv) {
    const char* event_str;
    switch(event_type) {
        case 0: event_str = "click"; break;
        case 1: event_str = "double_click"; break;
        case 2: event_str = "hold"; break;
        case -1:
            snprintf(last_flic_event, sizeof(last_flic_event),
                    "Button %s paired", button_mac);
            flic_buttons_paired++;
            send_flic_pairing_result(button_mac, "paired", "Unknown Button");

            if (pairing_mode_enabled) {
                ESP_LOGI(TAG, "Auto-disabling pairing mode after successful pairing");
                pairing_mode_enabled = false;
                if (pairing_timeout_timer) {
                    esp_timer_stop(pairing_timeout_timer);
                }
            }
            return;
        default:
            ESP_LOGD(TAG, "Ignoring event type %d from %s", event_type, button_mac);
            return;
    }

    snprintf(last_flic_event, sizeof(last_flic_event),
            "Button %s: %s (%d%%)", button_mac, event_str, calculate_battery_percentage(battery_mv));

    ESP_LOGI(TAG, "Flic button %s: %s (battery: %d%%)", button_mac, event_str, calculate_battery_percentage(battery_mv));

    if (!enqueue_button_event(button_mac, event_str, battery_mv)) {
        ESP_LOGW(TAG, "Failed to enqueue button event");
    }
}


static void discover_server_task(void *pvParameters) {
    while (!ethernet_connected) {
        ESP_LOGI(TAG, "Waiting for network connection...");
        vTaskDelay(pdMS_TO_TICKS(2000));
    }

    vTaskDelay(pdMS_TO_TICKS(3000));

    ESP_LOGI(TAG, "=== Starting Server Discovery ===");

    if (discover_server_via_mdns() == ESP_OK) {
        ESP_LOGI(TAG, "Server discovered via mDNS");
        send_device_discovery();
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "mDNS discovery failed, trying network scan...");

    if (discover_server_fallback() == ESP_OK) {
        ESP_LOGI(TAG, "Server discovered via network scan");
        send_device_discovery();
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGE(TAG, "Server discovery failed!");
    ESP_LOGI(TAG, "Please check:");
    ESP_LOGI(TAG, "  1. Server is on the same network");
    ESP_LOGI(TAG, "  2. Server service is running on port 5000");
    ESP_LOGI(TAG, "  3. No firewall blocking connections");

    while (!server_discovered) {
        ESP_LOGW(TAG, "Retrying Server discovery in 30 seconds...");
        vTaskDelay(pdMS_TO_TICKS(30000));

        if (discover_server_via_mdns() == ESP_OK || discover_server_fallback() == ESP_OK) {
            ESP_LOGI(TAG, "Server discovered on retry!");
            send_device_discovery();
            break;
        }
    }

    vTaskDelete(NULL);
}

static void heartbeat_task(void *pvParameters) {
    ESP_LOGI(TAG, "Heartbeat task started");

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(HEARTBEAT_INTERVAL_MS));

        if (server_discovered) {
            ESP_LOGI(TAG, "Sending heartbeat to server");
            send_heartbeat();
        } else {
            ESP_LOGW(TAG, "Heartbeat skipped - server not discovered");
        }
    }
}

void app_main(void) {
    ESP_LOGI(TAG, "ESP32-S3 Flic Gateway starting...");

    init_status_led();
    blink_status_led(3, 200);

    ESP_ERROR_CHECK(nvs_flash_init());

    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_ETH);
    snprintf(device_mac, sizeof(device_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    ESP_LOGI(TAG, "Device MAC: %s", device_mac);

    queued_events_mutex = xSemaphoreCreateMutex();
    if (!queued_events_mutex) {
        ESP_LOGE(TAG, "Failed to create queue mutex!");
        return;
    }

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(gpio_install_isr_service(0));

    eth_netif = esp_netif_new(&(esp_netif_config_t)ESP_NETIF_DEFAULT_ETH());
    esp_netif_dhcpc_option(eth_netif, ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER, "8.8.8.8", strlen("8.8.8.8"));
    esp_netif_set_hostname(eth_netif, "esp32s3-flic");

    ethernet_init();
    start_http_server();

    init_pairing_timeout_timer();

    ESP_LOGI(TAG, "ESP32-S3 Flic Gateway started");

    xTaskCreate(network_monitor_task, "network_monitor", 2048, NULL, 3, NULL);
    xTaskCreate(discover_server_task, "server_discovery", 4096, NULL, 5, NULL);
    xTaskCreate(button_event_processor_task, "btn_processor", 4096, NULL, 4, NULL);

    while (!ethernet_connected) {
        ESP_LOGI(TAG, "Waiting for network connection...");
        vTaskDelay(pdMS_TO_TICKS(3000));
    }
    ESP_LOGI(TAG, "Network connected!");

    while (!server_discovered) {
        ESP_LOGI(TAG, "Waiting for server discovery...");
        vTaskDelay(pdMS_TO_TICKS(2000));
    }
    ESP_LOGI(TAG, "Server discovered!");

    ESP_LOGI(TAG, "Initializing Flic2 wrapper...");
    esp_err_t ret = flic2_esp32_init(flic_button_event_callback);
    if (ret == ESP_OK) {
        flic_buttons_paired = flic2_esp32_get_paired_count();
        ble_controller_initialized = true;
        flic2_library_initialized = true;
        strcpy(flic_init_error, "");
        ESP_LOGI(TAG, "Flic2 wrapper initialized successfully");

        vTaskDelay(pdMS_TO_TICKS(1000));
        ret = flic2_esp32_start_scan();
        if (ret == ESP_OK) {
            flic_scanning_active = true;
            ESP_LOGI(TAG, "Flic scanning started - ready for button pairing!");
            ESP_LOGI(TAG, "Hold Flic button for 7+ seconds until rapid flashing to pair");
        } else {
            flic_scanning_active = false;
            snprintf(flic_init_error, sizeof(flic_init_error),
                    "Flic scanning failed: %s", esp_err_to_name(ret));
            ESP_LOGE(TAG, "%s", flic_init_error);
        }
    } else {
        ble_controller_initialized = false;
        flic2_library_initialized = false;
        snprintf(flic_init_error, sizeof(flic_init_error),
                "Flic2 wrapper init failed: %s", esp_err_to_name(ret));
        ESP_LOGE(TAG, "%s", flic_init_error);
        ESP_LOGW(TAG, "Flic functionality disabled, but network still works");
    }

    xTaskCreate(heartbeat_task, "heartbeat", 4096, NULL, 3, &heartbeat_task_handle);

    ESP_LOGI(TAG, "=== ESP32 Flic Gateway Ready ===");

    while (1) {
        ESP_LOGI(TAG, "Status: Network=%s, Server=%s, Pairing=%s, BLE=%s, Flic=%s, Scanning=%s",
                 ethernet_connected ? "OK" : "FAIL",
                 server_discovered ? "OK" : "FAIL",
                 pairing_mode_enabled ? "ON" : "OFF",
                 ble_controller_initialized ? "OK" : "FAIL",
                 flic2_library_initialized ? "OK" : "FAIL",
                 flic_scanning_active ? "ON" : "OFF");
        vTaskDelay(pdMS_TO_TICKS(60000));
    }
}