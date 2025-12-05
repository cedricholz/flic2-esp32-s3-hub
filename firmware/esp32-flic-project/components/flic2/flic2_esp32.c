#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/timers.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "cJSON.h"

#include "host/ble_hs.h"
#include "host/ble_uuid.h"
#include "host/ble_gatt.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

#include "flic2_esp32.h"

static const char *TAG = "FLIC2_ESP32";

extern bool pairing_mode_enabled;

typedef struct {
    uint8_t remote_bda[6];
    char mac_address[18];
    struct Flic2DbData flic_data;
} stored_button_t;

static SemaphoreHandle_t s_flic_mutex = NULL;

#define FLIC_EVENT_CLASS_TO_FORWARD FLIC2_EVENT_BUTTON_EVENT_CLASS_SINGLE_OR_DOUBLE_CLICK_OR_HOLD

static inline void flic_lock(void) {
    if (s_flic_mutex) xSemaphoreTake(s_flic_mutex, portMAX_DELAY);
}
static inline void flic_unlock(void) {
    if (s_flic_mutex) xSemaphoreGive(s_flic_mutex);
}

static flic_device_t flic_devices[MAX_FLIC_BUTTONS];
static int num_flic_devices = 0;
static flic_event_callback_t event_callback = NULL;
static bool scanning = false;
static struct ble_gap_disc_params disc_params;

static void process_flic_events(flic_device_t *device);
static int gap_event_cb(struct ble_gap_event *event, void *arg);

static void start_scanning_if_needed(void);

static esp_timer_handle_t reconnect_timer = NULL;
#define RECONNECT_SCAN_INTERVAL_MS 30000
static int64_t last_scan_time = 0;

static const ble_uuid128_t flic2_service_uuid =
    BLE_UUID128_INIT(0x93, 0xe4, 0x17, 0xb6, 0xf3, 0x84, 0x0d, 0x87,
                     0x20, 0x44, 0x59, 0x8f, 0x00, 0x00, 0x42, 0x00);

static const ble_uuid128_t flic2_write_char_uuid =
    BLE_UUID128_INIT(0x93, 0xe4, 0x17, 0xb6, 0xf3, 0x84, 0x0d, 0x87,
                     0x20, 0x44, 0x59, 0x8f, 0x01, 0x00, 0x42, 0x00);

static const ble_uuid128_t flic2_notify_char_uuid =
    BLE_UUID128_INIT(0x93, 0xe4, 0x17, 0xb6, 0xf3, 0x84, 0x0d, 0x87,
                     0x20, 0x44, 0x59, 0x8f, 0x02, 0x00, 0x42, 0x00);

static bool is_known_flic_mac(const uint8_t *bda) {
    for (int i = 0; i < num_flic_devices; i++) {
        if (memcmp(flic_devices[i].remote_bda, bda, 6) == 0) {
            return true;
        }
    }
    return false;
}

static int count_disconnected_buttons(void) {
    int count = 0;
    for (int i = 0; i < num_flic_devices; i++) {
        if (!flic_devices[i].connected) {
            count++;
        }
    }
    return count;
}

static void print_connection_status(void) {
    ESP_LOGI(TAG, "=== CONNECTION STATUS ===");
    ESP_LOGI(TAG, "Total paired buttons: %d", num_flic_devices);

    int connected_count = 0;
    for (int i = 0; i < num_flic_devices; i++) {
        const char *status = flic_devices[i].connected ? "CONNECTED" : "DISCONNECTED";
        ESP_LOGI(TAG, "  [%d] %s: %s (handle: %d)",
                 i, flic_devices[i].mac_address, status, flic_devices[i].conn_handle);
        if (flic_devices[i].connected) connected_count++;
    }

    ESP_LOGI(TAG, "Connected: %d, Disconnected: %d, Scanning: %s",
             connected_count, num_flic_devices - connected_count,
             scanning ? "YES" : "NO");
    ESP_LOGI(TAG, "========================");
}

static void reconnect_timer_callback(void* arg) {
    ESP_LOGD(TAG, "Reconnect timer fired");

    int disconnected = count_disconnected_buttons();
    if (disconnected > 0) {
        ESP_LOGI(TAG, "Reconnect check: %d button(s) disconnected", disconnected);
        print_connection_status();
        start_scanning_if_needed();
    }
}

static void start_reconnect_timer(void) {
    if (!reconnect_timer) {
        esp_timer_create_args_t timer_args = {
            .callback = reconnect_timer_callback,
            .arg = NULL,
            .name = "flic_reconnect"
        };
        esp_timer_create(&timer_args, &reconnect_timer);
    }

    esp_timer_stop(reconnect_timer);
    esp_timer_start_periodic(reconnect_timer, RECONNECT_SCAN_INTERVAL_MS * 1000);
    ESP_LOGI(TAG, "Started reconnect timer (interval: %d ms)", RECONNECT_SCAN_INTERVAL_MS);
}

static void start_scanning_if_needed(void) {
    if (!scanning) {
        int64_t now = esp_timer_get_time() / 1000;
        if (now - last_scan_time < 1000) {
            ESP_LOGD(TAG, "Skipping scan - too soon since last scan");
            return;
        }

        ESP_LOGI(TAG, "Starting BLE scan for reconnection...");
        int rc = ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &disc_params, gap_event_cb, NULL);
        if (rc == 0) {
            scanning = true;
            last_scan_time = now;
            ESP_LOGI(TAG, "Scan started successfully");
        } else {
            ESP_LOGW(TAG, "Failed to start scan: %d", rc);
        }
    } else {
        ESP_LOGD(TAG, "Already scanning");
    }
}

static double get_steady_clock_s(void) {
    return (double)esp_timer_get_time() / 1000000.0;
}

static bool is_flic2_button_adv(const uint8_t *adv_data, uint8_t adv_data_len, bool *is_in_pairing_mode) {
    *is_in_pairing_mode = false;
    bool has_flic_uuid = false;
    bool has_flic_name = false;

    for (int i = 0; i < adv_data_len - 1; i++) {
        uint8_t len = adv_data[i];
        if (i + len >= adv_data_len) break;

        uint8_t type = adv_data[i + 1];

        // Check for name
        if ((type == 0x09 || type == 0x08) && len >= 3) {
            if (i + 3 < adv_data_len && adv_data[i + 2] == 'F' && adv_data[i + 3] == '2') {
                has_flic_name = true;
                ESP_LOGD(TAG, "Found Flic2 name in advertisement");
            }
        }

        // Check for UUID
        if (type == 0x07 && len == 17) {
            uint8_t flic2_uuid[] = {0x93, 0xE4, 0x17, 0xB6, 0xF3, 0x84, 0x0D, 0x87,
                                   0x20, 0x44, 0x59, 0x8F, 0x00, 0x00, 0x42, 0x00};
            if (memcmp(&adv_data[i + 2], flic2_uuid, 16) == 0) {
                has_flic_uuid = true;
                ESP_LOGD(TAG, "Found Flic2 UUID in advertisement");
            }
        }

        i += len;
    }

    *is_in_pairing_mode = has_flic_name;
    return has_flic_uuid || has_flic_name;
}

int flic2_esp32_get_paired_count(void) {
    return num_flic_devices;
}

static double get_system_clock_s(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}

static void generate_random_bytes(uint8_t *out, size_t len) {
    esp_fill_random(out, len);
}

static flic_device_t* find_device_by_mac(const uint8_t *bda) {
    for (int i = 0; i < num_flic_devices; i++) {
        if (memcmp(flic_devices[i].remote_bda, bda, 6) == 0) {
            return &flic_devices[i];
        }
    }
    return NULL;
}

cJSON* flic2_esp32_get_paired_buttons_json(void) {
    cJSON *paired_button_macs = cJSON_CreateArray();
    for (int i = 0; i < num_flic_devices; i++) {
        cJSON *button_obj = cJSON_CreateObject();
        cJSON *mac_address = cJSON_CreateString(flic_devices[i].mac_address);
        cJSON_AddItemToObject(button_obj, "mac_address", mac_address);
        cJSON_AddItemToArray(paired_button_macs, button_obj);
    }
    return paired_button_macs;
}

static flic_device_t* find_device_by_conn_handle(uint16_t conn_handle) {
    for (int i = 0; i < num_flic_devices; i++) {
        if (flic_devices[i].conn_handle == conn_handle) {
            return &flic_devices[i];
        }
    }
    return NULL;
}

static void timer_callback(void* arg) {
    flic_device_t *device = (flic_device_t*)arg;
    if (!device) return;

    flic_lock();
    double current_time = get_steady_clock_s();
    flic2_on_timer(&device->button, current_time);
    process_flic_events(device);
    flic_unlock();
}

static void delete_button_from_nvs(const uint8_t *bda) {
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("flic_buttons", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) return;

    uint32_t hash = 0;
    for (int i = 0; i < 6; i++) {
        hash = hash * 31 + bda[i];
    }
    char key[16];
    snprintf(key, sizeof(key), "btn_%08lx", hash);

    nvs_erase_key(nvs_handle, key);
    nvs_commit(nvs_handle);
    nvs_close(nvs_handle);
}

static void save_button_to_nvs(flic_device_t *device) {
    ESP_LOGI(TAG, "Saving button %s to NVS", device->mac_address);

    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("flic_buttons", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS for writing: %s", esp_err_to_name(err));
        return;
    }

    uint32_t hash = 0;
    for (int i = 0; i < 6; i++) {
        hash = hash * 31 + device->remote_bda[i];
    }
    char key[16];
    snprintf(key, sizeof(key), "btn_%08lx", hash);

    // Check if this button is already stored under a different key
    nvs_iterator_t it = NULL;
    err = nvs_entry_find(NVS_DEFAULT_PART_NAME, "flic_buttons", NVS_TYPE_BLOB, &it);

    while (err == ESP_OK) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);

        if (strncmp(info.key, "btn_", 4) == 0 && strcmp(info.key, key) != 0) {
            stored_button_t existing_data;
            size_t required_size = sizeof(stored_button_t);

            if (nvs_get_blob(nvs_handle, info.key, &existing_data, &required_size) == ESP_OK) {
                if (memcmp(existing_data.remote_bda, device->remote_bda, 6) == 0) {
                    ESP_LOGW(TAG, "Found duplicate button under different key %s, deleting it", info.key);
                    nvs_erase_key(nvs_handle, info.key);
                }
            }
        }

        err = nvs_entry_next(&it);
    }

    if (it) {
        nvs_release_iterator(it);
    }

    stored_button_t stored_data;
    memcpy(stored_data.remote_bda, device->remote_bda, 6);
    strcpy(stored_data.mac_address, device->mac_address);
    stored_data.flic_data = device->button.d;

    err = nvs_set_blob(nvs_handle, key, &stored_data, sizeof(stored_button_t));
    if (err == ESP_OK) {
        err = nvs_commit(nvs_handle);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "Successfully saved button %s to NVS", device->mac_address);
        } else {
            ESP_LOGE(TAG, "Failed to commit button %s to NVS: %s", device->mac_address, esp_err_to_name(err));
        }
    } else {
        ESP_LOGE(TAG, "Failed to write button %s to NVS: %s", device->mac_address, esp_err_to_name(err));
    }

    nvs_close(nvs_handle);
}

static esp_err_t load_all_buttons_from_nvs(void) {
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("flic_buttons", NVS_READONLY, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGI(TAG, "No stored buttons found in NVS: %s", esp_err_to_name(err));
        return err;
    }

    nvs_iterator_t it = NULL;
    err = nvs_entry_find(NVS_DEFAULT_PART_NAME, "flic_buttons", NVS_TYPE_BLOB, &it);
    while (err == ESP_OK) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);

        if (strncmp(info.key, "btn_", 4) != 0) {
            err = nvs_entry_next(&it);
            continue;
        }

        if (num_flic_devices >= MAX_FLIC_BUTTONS) {
            ESP_LOGW(TAG, "Maximum number of Flic buttons reached, skipping %s", info.key);
            break;
        }

        stored_button_t stored_data;
        size_t required_size = sizeof(stored_button_t);
        esp_err_t read_err = nvs_get_blob(nvs_handle, info.key, &stored_data, &required_size);

        if (read_err == ESP_OK) {
            flic_device_t *device = &flic_devices[num_flic_devices];
            memset(device, 0, sizeof(flic_device_t));

            memcpy(device->remote_bda, stored_data.remote_bda, 6);
            strcpy(device->mac_address, stored_data.mac_address);

            ESP_LOGI(TAG, "Loading button %s from NVS", device->mac_address);
            ESP_LOGI(TAG, "Loaded pairing data (first 8 bytes): %02x %02x %02x %02x %02x %02x %02x %02x",
                     stored_data.flic_data.pairing[0], stored_data.flic_data.pairing[1],
                     stored_data.flic_data.pairing[2], stored_data.flic_data.pairing[3],
                     stored_data.flic_data.pairing[4], stored_data.flic_data.pairing[5],
                     stored_data.flic_data.pairing[6], stored_data.flic_data.pairing[7]);

            uint8_t bd_addr_le[6];
            for (int i = 0; i < 6; i++) bd_addr_le[i] = device->remote_bda[5 - i];

            uint8_t rand_seed[16];
            generate_random_bytes(rand_seed, 16);

            double now_s = get_steady_clock_s();

            flic2_init(&device->button, bd_addr_le, &stored_data.flic_data, rand_seed, now_s);

            esp_timer_create_args_t timer_args = {
                .callback = timer_callback,
                .arg = device,
                .name = "flic_timer"
            };
            esp_timer_create(&timer_args, &device->timer_handle);

            ESP_LOGI(TAG, "Restored paired button: %s", device->mac_address);
            num_flic_devices++;
        } else {
            ESP_LOGW(TAG, "Failed to load button data for %s: %s", info.key, esp_err_to_name(read_err));
        }

        err = nvs_entry_next(&it);
    }

    if (it) {
        nvs_release_iterator(it);
    }
    nvs_close(nvs_handle);

    ESP_LOGI(TAG, "Loaded %d paired buttons from NVS", num_flic_devices);
    return ESP_OK;
}

int flic2_count_paired_buttons_in_nvs(void) {
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("flic_buttons", NVS_READONLY, &nvs_handle);
    if (err != ESP_OK) {
        return 0;
    }

    int count = 0;
    nvs_iterator_t it = NULL;
    err = nvs_entry_find(NVS_DEFAULT_PART_NAME, "flic_buttons", NVS_TYPE_BLOB, &it);
    while (err == ESP_OK) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);

        if (strncmp(info.key, "btn_", 4) == 0) {
            count++;
        }

        err = nvs_entry_next(&it);
    }

    if (it) {
        nvs_release_iterator(it);
    }
    nvs_close(nvs_handle);

    return count;
}

static void process_flic_events(flic_device_t *device) {
    struct Flic2Event flic_event;
    double current_utc_time = get_system_clock_s();
    double current_time = get_steady_clock_s();
    bool needs_save = false;
    static uint32_t last_save_time[MAX_FLIC_BUTTONS] = {0};
    const uint32_t MIN_SAVE_INTERVAL_MS = 30000;

    while (flic2_get_next_event(&device->button, current_utc_time, current_time, &flic_event, true)) {

        if (flic_event.db_update.type != FLIC2_DB_UPDATE_TYPE_NONE) {
            if (flic_event.db_update.type == FLIC2_DB_UPDATE_TYPE_DELETE) {
                delete_button_from_nvs(device->remote_bda);
                memset(&device->button.d, 0, sizeof(device->button.d));
            } else if (flic_event.db_update.type == FLIC2_DB_UPDATE_TYPE_ADD) {
                needs_save = true;
                ESP_LOGI(TAG, "New button paired - will save to NVS");
            } else if (flic_event.db_update.type == FLIC2_DB_UPDATE_TYPE_UPDATE) {
                uint32_t critical_fields = FLIC2_DB_FIELD_PAIRING |
                                          FLIC2_DB_FIELD_NAME |
                                          FLIC2_DB_FIELD_UUID |
                                          FLIC2_DB_FIELD_SERIAL_NUMBER;

                uint32_t excluded_fields = FLIC2_DB_FIELD_EVENT_COUNT |
                                          FLIC2_DB_FIELD_BOOT_ID |
                                          FLIC2_DB_FIELD_BATTERY_VOLTAGE_MILLIVOLT |
                                          FLIC2_DB_FIELD_BATTERY_TIMESTAMP_UTC_MS |
                                          FLIC2_DB_FIELD_FIRMWARE_VERSION;

                uint32_t filtered_mask = flic_event.db_update.field_update_mask &
                                        critical_fields &
                                        ~excluded_fields;

                if (filtered_mask != 0) {
                    uint32_t now = xTaskGetTickCount() * portTICK_PERIOD_MS;
                    int device_index = device - flic_devices;

                    if (device_index >= 0 && device_index < MAX_FLIC_BUTTONS) {
                        if (now - last_save_time[device_index] >= MIN_SAVE_INTERVAL_MS) {
                            needs_save = true;
                            last_save_time[device_index] = now;
                            ESP_LOGI(TAG, "Critical field updated for %s - will save to NVS (mask: 0x%lx)",
                                    device->mac_address, filtered_mask);
                        } else {
                            ESP_LOGD(TAG, "Skipping NVS save for %s - too soon since last save",
                                    device->mac_address);
                        }
                    }
                }
            }
        }

        switch (flic_event.type) {
            case FLIC2_EVENT_TYPE_SET_TIMER: {
                if (device->timer_handle) {
                    esp_timer_stop(device->timer_handle);
                }
                uint64_t timeout_us = 0;
                if (flic_event.event.set_timer.absolute_time > current_time) {
                    timeout_us = (uint64_t)((flic_event.event.set_timer.absolute_time - current_time) * 1000000.0);
                }
                if (timeout_us > 0 && device->timer_handle) {
                    esp_timer_start_once(device->timer_handle, timeout_us);
                }
                break;
            }

            case FLIC2_EVENT_TYPE_ABORT_TIMER: {
                if (device->timer_handle) {
                    esp_timer_stop(device->timer_handle);
                }
                break;
            }

            case FLIC2_EVENT_TYPE_OUTGOING_PACKET: {
                if (device->connected && device->write_handle != 0) {
                    struct os_mbuf *om = ble_hs_mbuf_from_flat(
                        flic_event.event.outgoing_packet.data,
                        flic_event.event.outgoing_packet.len
                    );

                    if (om) {
                        int rc = ble_gattc_write_no_rsp(device->conn_handle, device->write_handle, om);
                        if (rc != 0) {
                            ESP_LOGW(TAG, "Write failed: %d", rc);
                        }
                    }
                }
                break;
            }

            case FLIC2_EVENT_TYPE_PAIRED: {
                ESP_LOGI(TAG, "Button PAIRED: %s", device->mac_address);
                save_button_to_nvs(device);
                if (event_callback) {
                    event_callback(device->mac_address, -1, device->button.d.battery_voltage_millivolt);
                }
                break;
            }

            case FLIC2_EVENT_TYPE_BUTTON_EVENT: {
                if (flic_event.event.button_event.event_class != FLIC_EVENT_CLASS_TO_FORWARD) {
                    break;
                }

                if (event_callback) {
                    int event_type = -2;
                    switch (flic_event.event.button_event.event_type) {
                        case FLIC2_EVENT_BUTTON_EVENT_TYPE_SINGLE_CLICK: event_type = 0; break;
                        case FLIC2_EVENT_BUTTON_EVENT_TYPE_DOUBLE_CLICK: event_type = 1; break;
                        case FLIC2_EVENT_BUTTON_EVENT_TYPE_HOLD:         event_type = 2; break;
                        default:
                            break;
                    }
                    if (event_type >= 0) {
                        event_callback(device->mac_address, event_type, device->button.d.battery_voltage_millivolt);
                    }
                }
                break;
            }

            case FLIC2_EVENT_TYPE_UNPAIRED: {
                ESP_LOGI(TAG, "Button UNPAIRED by device: %s", device->mac_address);
                if (device->connected) {
                    ble_gap_terminate(device->conn_handle, BLE_ERR_REM_USER_CONN_TERM);
                    device->connected = false;
                }
                if (!scanning) {
                    ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &disc_params, gap_event_cb, NULL);
                    scanning = true;
                }
                break;
            }

            case FLIC2_EVENT_TYPE_PAIRING_FAILED: {
                ESP_LOGW(TAG, "Pairing FAILED (%u/%u) with %s",
                         (unsigned)flic_event.event.pairing_failed.error_code,
                         (unsigned)flic_event.event.pairing_failed.subcode,
                         device->mac_address);
                if (device->connected) {
                    ble_gap_terminate(device->conn_handle, BLE_ERR_REM_USER_CONN_TERM);
                    device->connected = false;
                }
                if (!scanning) {
                    ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &disc_params, gap_event_cb, NULL);
                    scanning = true;
                }
                break;
            }

            case FLIC2_EVENT_TYPE_SESSION_FAILED: {
                ESP_LOGW(TAG, "Session FAILED (%u/%u) with %s",
                         (unsigned)flic_event.event.session_failed.error_code,
                         (unsigned)flic_event.event.session_failed.subcode,
                         device->mac_address);
                if (device->connected) {
                    ble_gap_terminate(device->conn_handle, BLE_ERR_REM_USER_CONN_TERM);
                    device->connected = false;
                }
                if (!scanning) {
                    ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &disc_params, gap_event_cb, NULL);
                    scanning = true;
                }
                break;
            }

            case FLIC2_EVENT_TYPE_REAUTHENTICATED: {
                ESP_LOGI(TAG, "Reauthenticated: %s", device->mac_address);
                break;
            }

            case FLIC2_EVENT_TYPE_NAME_UPDATED: {
                ESP_LOGI(TAG, "Name updated for %s: %.*s",
                         device->mac_address,
                         flic_event.event.name_updated.length_bytes,
                         flic_event.event.name_updated.name);
                break;
            }

            case FLIC2_EVENT_TYPE_BATTERY_VOLTAGE_UPDATED: {
                ESP_LOGI(TAG, "Battery %s: %d mV",
                         device->mac_address,
                         (int)flic_event.event.battery_voltage_updated.millivolt);
                break;
            }

            case FLIC2_EVENT_TYPE_CHECK_FIRMWARE_REQUEST: {
                ESP_LOGI(TAG, "Check FW request: cur=%u for %s",
                         (unsigned)flic_event.event.check_firmware_request.current_version,
                         device->mac_address);
                break;
            }

            case FLIC2_EVENT_TYPE_FIRMWARE_VERSION_UPDATED: {
                ESP_LOGI(TAG, "FW version updated %s: %u",
                         device->mac_address,
                         (unsigned)flic_event.event.firmware_version_updated.firmware_version);
                break;
            }

            case FLIC2_EVENT_TYPE_ONLY_DB_UPDATE:
            case FLIC2_EVENT_TYPE_NONE:
            default:
                break;
        }
    }

    if (needs_save) {
        save_button_to_nvs(device);
    }
}

static int gatt_disc_char_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                             const struct ble_gatt_chr *chr, void *arg) {
    flic_device_t *device = (flic_device_t *)arg;

    if (error->status != 0 && error->status != BLE_HS_EDONE) {
        ESP_LOGW(TAG, "Characteristic discovery error: %d", error->status);
        return 0;
    }

    if (chr == NULL) {
        ESP_LOGI(TAG, "Characteristic discovery complete");

        if (device->write_handle == 0 || device->notify_handle == 0) {
            ESP_LOGW(TAG, "Required characteristics missing");
            ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
            if (!scanning) {
                ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &disc_params, gap_event_cb, NULL);
                scanning = true;
            }
            return 0;
        }

        uint8_t notify_en[2] = {0x01, 0x00};
        uint16_t cccd_handle = device->notify_handle + 1;
        ESP_LOGI(TAG, "Writing CCCD to enable notifications (handle: 0x%04x)", cccd_handle);
        int rc = ble_gattc_write_flat(conn_handle, cccd_handle, notify_en, sizeof(notify_en), NULL, NULL);
        if (rc != 0) {
            ESP_LOGW(TAG, "Failed to enable notifications: %d", rc);
        } else {
            ESP_LOGI(TAG, "Notifications enabled successfully");
        }

        flic_lock();
        double current_time = get_steady_clock_s();

        bool has_pairing_data = false;
        for (int i = 0; i < 20; i++) {
            if (device->button.d.pairing[i] != 0) {
                has_pairing_data = true;
                break;
            }
        }

        ESP_LOGI(TAG, "Button %s - has_pairing_data: %s",
                 device->mac_address, has_pairing_data ? "YES" : "NO");

        ESP_LOGI(TAG, "Starting Flic2 session for %s", device->mac_address);
        flic2_start(&device->button, current_time, 130);

        process_flic_events(device);
        flic_unlock();

        if (!scanning) {
            ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &disc_params, gap_event_cb, NULL);
            scanning = true;
            ESP_LOGI(TAG, "Resumed scanning for additional buttons");
        }

        return 0;
    }

    if (ble_uuid_cmp(&chr->uuid.u, &flic2_write_char_uuid.u) == 0) {
        device->write_handle = chr->val_handle;
        ESP_LOGI(TAG, "Found write characteristic handle: 0x%04x", device->write_handle);
    } else if (ble_uuid_cmp(&chr->uuid.u, &flic2_notify_char_uuid.u) == 0) {
        device->notify_handle = chr->val_handle;
        ESP_LOGI(TAG, "Found notify characteristic handle: 0x%04x", device->notify_handle);
    }

    return 0;
}

static int gatt_disc_svc_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                            const struct ble_gatt_svc *svc, void *arg) {
    flic_device_t *device = (flic_device_t *)arg;

    if (error->status != 0 && error->status != BLE_HS_EDONE) {
        ESP_LOGW(TAG, "Service discovery error: %d", error->status);
        return 0;
    }

    if (svc == NULL) {
        ESP_LOGI(TAG, "Service discovery complete");

        if (device->service_start_handle == 0 || device->service_end_handle == 0) {
            ESP_LOGW(TAG, "Flic2 service not found");
            ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
            if (!scanning) {
                ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &disc_params, gap_event_cb, NULL);
                scanning = true;
            }
            return 0;
        }

        ESP_LOGI(TAG, "Discovering characteristics in service range 0x%04x-0x%04x",
                 device->service_start_handle, device->service_end_handle);
        ble_gattc_disc_all_chrs(conn_handle, device->service_start_handle,
                               device->service_end_handle, gatt_disc_char_cb, device);
        return 0;
    }

    char uuid_str[BLE_UUID_STR_LEN];
    ble_uuid_to_str(&svc->uuid.u, uuid_str);
    ESP_LOGI(TAG, "Found service UUID: %s, handles: 0x%04x-0x%04x",
             uuid_str, svc->start_handle, svc->end_handle);

    if (ble_uuid_cmp(&svc->uuid.u, &flic2_service_uuid.u) == 0) {
        device->service_start_handle = svc->start_handle;
        device->service_end_handle = svc->end_handle;
        ESP_LOGI(TAG, "*** FOUND Flic2 service! Range: 0x%04x–0x%04x",
                 device->service_start_handle, device->service_end_handle);
    }

    return 0;
}

static int gap_event_cb(struct ble_gap_event *event, void *arg) {
    switch (event->type) {
        case BLE_GAP_EVENT_DISC: {
            const struct ble_gap_disc_desc *disc = &event->disc;

            bool is_in_pairing_mode = false;
            bool is_flic = is_flic2_button_adv(disc->data, disc->length_data, &is_in_pairing_mode);
            bool is_known = is_known_flic_mac(disc->addr.val);

            char mac_str[18];
            sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
                    disc->addr.val[5], disc->addr.val[4], disc->addr.val[3],
                    disc->addr.val[2], disc->addr.val[1], disc->addr.val[0]);

            if (is_flic || is_known) {
                ESP_LOGD(TAG, "Flic detected: %s (RSSI: %d, known: %s, pairing_mode: %s)",
                        mac_str, disc->rssi, is_known ? "YES" : "NO",
                        is_in_pairing_mode ? "YES" : "NO");
            }

            bool should_connect = false;
            if (is_in_pairing_mode && pairing_mode_enabled && !is_known) {
                ESP_LOGI(TAG, "New Flic in pairing mode detected: %s", mac_str);
                should_connect = true;
            } else if (is_known) {
                flic_device_t *device = find_device_by_mac(disc->addr.val);
                if (device && !device->connected) {
                    ESP_LOGI(TAG, "Known Flic detected for reconnection: %s", mac_str);
                    should_connect = true;
                }
            }

            if (should_connect) {
                ESP_LOGI(TAG, "Attempting to connect to %s", mac_str);

                ble_gap_disc_cancel();
                scanning = false;

                int rc = ble_gap_connect(BLE_OWN_ADDR_PUBLIC, &disc->addr,
                                        30000, NULL, gap_event_cb, NULL);

                if (rc != 0) {
                    ESP_LOGW(TAG, "Connection attempt failed: %d", rc);
                    start_scanning_if_needed();
                } else {
                    ESP_LOGI(TAG, "Connection initiated for %s", mac_str);
                }
            }
            break;
        }

        case BLE_GAP_EVENT_CONNECT: {
            if (event->connect.status == 0) {
                ESP_LOGI(TAG, "Connection established (handle: %d)", event->connect.conn_handle);

                struct ble_gap_conn_desc desc;
                ble_gap_conn_find(event->connect.conn_handle, &desc);

                char mac_str[18];
                sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
                        desc.peer_ota_addr.val[5], desc.peer_ota_addr.val[4],
                        desc.peer_ota_addr.val[3], desc.peer_ota_addr.val[2],
                        desc.peer_ota_addr.val[1], desc.peer_ota_addr.val[0]);

                ESP_LOGI(TAG, "Connected to: %s", mac_str);

                flic_device_t *device = find_device_by_mac(desc.peer_ota_addr.val);

                if (!device && num_flic_devices < MAX_FLIC_BUTTONS) {
                    // New device for pairing
                    device = &flic_devices[num_flic_devices++];
                    memset(device, 0, sizeof(flic_device_t));

                    memcpy(device->remote_bda, desc.peer_ota_addr.val, 6);
                    strcpy(device->mac_address, mac_str);

                    uint8_t rand_seed[16];
                    generate_random_bytes(rand_seed, 16);

                    double now_s = get_steady_clock_s();
                    flic2_init(&device->button, desc.peer_ota_addr.val, NULL, rand_seed, now_s);

                    esp_timer_create_args_t timer_args = {
                        .callback = timer_callback,
                        .arg = device,
                        .name = "flic_timer"
                    };
                    esp_timer_create(&timer_args, &device->timer_handle);

                    ESP_LOGI(TAG, "Created new device for pairing: %s", device->mac_address);
                } else if (!device) {
                    ESP_LOGE(TAG, "Maximum buttons reached or device not found");
                    ble_gap_terminate(event->connect.conn_handle, BLE_ERR_REM_USER_CONN_TERM);
                    start_scanning_if_needed();
                    break;
                } else {
                    ESP_LOGI(TAG, "Reconnected to existing device: %s", device->mac_address);
                }

                device->conn_handle = event->connect.conn_handle;
                device->connected = true;

                print_connection_status();

                ble_att_set_preferred_mtu(517);
                ble_gattc_exchange_mtu(event->connect.conn_handle, NULL, NULL);

                ble_gattc_disc_all_svcs(event->connect.conn_handle, gatt_disc_svc_cb, device);
            } else {
                ESP_LOGW(TAG, "Connection failed: %d", event->connect.status);
                start_scanning_if_needed();
            }
            break;
        }

        case BLE_GAP_EVENT_DISCONNECT: {
            ESP_LOGI(TAG, "Disconnected (reason: %d)", event->disconnect.reason);
            flic_device_t *device = find_device_by_conn_handle(event->disconnect.conn.conn_handle);
            if (device) {
                ESP_LOGI(TAG, "Button %s disconnected", device->mac_address);
                device->connected = false;
                device->conn_handle = 0;
                device->write_handle = 0;
                device->notify_handle = 0;
                device->service_start_handle = 0;
                device->service_end_handle = 0;

                flic_lock();
                flic2_on_disconnected(&device->button);
                process_flic_events(device);
                flic_unlock();
            }

            print_connection_status();

            // Always try to scan after disconnect to reconnect
            vTaskDelay(pdMS_TO_TICKS(500));
            start_scanning_if_needed();
            break;
        }

        case BLE_GAP_EVENT_DISC_COMPLETE: {
            ESP_LOGI(TAG, "Discovery complete (reason: %d)", event->disc_complete.reason);
            scanning = false;

            // If we have disconnected buttons, keep trying
            int disconnected = count_disconnected_buttons();
            if (disconnected > 0) {
                ESP_LOGI(TAG, "Still have %d disconnected button(s), will retry scan", disconnected);
            }
            break;
        }

        case BLE_GAP_EVENT_MTU: {
            ESP_LOGI(TAG, "MTU updated: %d", event->mtu.value);
            break;
        }

        case BLE_GAP_EVENT_NOTIFY_RX: {

            flic_device_t *device = find_device_by_conn_handle(event->notify_rx.conn_handle);
            if (!device) {
                ESP_LOGW(TAG, "Notification for unknown device");
                break;
            }

            flic_lock();
            double current_utc_time = get_system_clock_s();
            double current_time = get_steady_clock_s();

            struct os_mbuf *om = event->notify_rx.om;
            uint8_t data[256];
            uint16_t len = OS_MBUF_PKTLEN(om);
            if (len > sizeof(data)) len = sizeof(data);

            os_mbuf_copydata(om, 0, len, data);

            ESP_LOGI(TAG, "Processing Flic notification: %d bytes", len);
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, data, len > 32 ? 32 : len, ESP_LOG_INFO);
            flic2_on_incoming_packet(&device->button, current_utc_time, current_time, data, len);
            process_flic_events(device);
            flic_unlock();
            break;
        }

        default:
            break;
    }

    return 0;
}

static void on_sync(void) {
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "NimBLE host synced - BLE is ready!");
    ESP_LOGI(TAG, "========================================");
}

static void on_reset(int reason) {
    ESP_LOGE(TAG, "========================================");
    ESP_LOGE(TAG, "NimBLE host reset (reason: %d)", reason);
    ESP_LOGE(TAG, "========================================");
}

static void nimble_host_task(void *param) {
    ESP_LOGI(TAG, "NimBLE host task started");
    nimble_port_run();
    nimble_port_freertos_deinit();
}

esp_err_t flic2_esp32_unpair_button(const char* mac_address) {
    ESP_LOGI(TAG, "Attempting to unpair button: %s", mac_address);

    flic_lock();

    uint8_t target_bda[6];
    bool have_target_bda = false;

    // First pass: find the button and get its BDA
    for (int i = 0; i < num_flic_devices; i++) {
        if (strcmp(flic_devices[i].mac_address, mac_address) == 0) {
            memcpy(target_bda, flic_devices[i].remote_bda, 6);
            have_target_bda = true;
            break;
        }
    }

    if (!have_target_bda) {
        flic_unlock();
        ESP_LOGW(TAG, "Button %s not found in paired devices", mac_address);
        return ESP_ERR_NOT_FOUND;
    }

    // Second pass: remove ALL instances from memory array
    int write_idx = 0;
    int removed_count = 0;
    for (int read_idx = 0; read_idx < num_flic_devices; read_idx++) {
        if (memcmp(flic_devices[read_idx].remote_bda, target_bda, 6) == 0) {
            ESP_LOGI(TAG, "Removing button instance %d: %s", removed_count, mac_address);

            if (flic_devices[read_idx].connected) {
                ble_gap_terminate(flic_devices[read_idx].conn_handle, BLE_ERR_REM_USER_CONN_TERM);
            }

            if (flic_devices[read_idx].timer_handle) {
                esp_timer_stop(flic_devices[read_idx].timer_handle);
                esp_timer_delete(flic_devices[read_idx].timer_handle);
            }

            removed_count++;
        } else {
            if (write_idx != read_idx) {
                flic_devices[write_idx] = flic_devices[read_idx];
            }
            write_idx++;
        }
    }

    num_flic_devices = write_idx;

    // Clean up any remaining slots
    for (int i = num_flic_devices; i < num_flic_devices + removed_count; i++) {
        memset(&flic_devices[i], 0, sizeof(flic_device_t));
    }

    // Delete ALL instances from NVS
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("flic_buttons", NVS_READWRITE, &nvs_handle);
    if (err == ESP_OK) {
        nvs_iterator_t it = NULL;
        err = nvs_entry_find(NVS_DEFAULT_PART_NAME, "flic_buttons", NVS_TYPE_BLOB, &it);

        while (err == ESP_OK) {
            nvs_entry_info_t info;
            nvs_entry_info(it, &info);

            if (strncmp(info.key, "btn_", 4) == 0) {
                stored_button_t stored_data;
                size_t required_size = sizeof(stored_button_t);

                if (nvs_get_blob(nvs_handle, info.key, &stored_data, &required_size) == ESP_OK) {
                    if (memcmp(stored_data.remote_bda, target_bda, 6) == 0) {
                        ESP_LOGI(TAG, "Deleting button from NVS key: %s", info.key);
                        nvs_erase_key(nvs_handle, info.key);
                    }
                }
            }

            err = nvs_entry_next(&it);
        }

        if (it) {
            nvs_release_iterator(it);
        }

        nvs_commit(nvs_handle);
        nvs_close(nvs_handle);
    }

    flic_unlock();

    ESP_LOGI(TAG, "Successfully unpaired %d instance(s) of button %s. Total paired buttons: %d",
             removed_count, mac_address, num_flic_devices);

    return ESP_OK;
}

esp_err_t flic2_esp32_init(flic_event_callback_t callback) {
    ESP_LOGI(TAG, "=== STARTING FLIC2 ESP32 INIT (NimBLE) ===");

    if (!callback) {
        ESP_LOGE(TAG, "Callback is NULL");
        return ESP_ERR_INVALID_ARG;
    }
    event_callback = callback;
    ESP_LOGI(TAG, "Callback set successfully");

    if (!s_flic_mutex) {
        s_flic_mutex = xSemaphoreCreateMutex();
        ESP_LOGI(TAG, "Mutex created");
    }

    ESP_LOGI(TAG, "Initializing NimBLE port...");
    esp_err_t ret = nimble_port_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "NimBLE port init FAILED: %s (0x%x)", esp_err_to_name(ret), ret);
        return ret;
    }
    ESP_LOGI(TAG, "NimBLE port initialized successfully");

    ESP_LOGI(TAG, "Setting up NimBLE callbacks...");
    ble_hs_cfg.sync_cb = on_sync;
    ble_hs_cfg.reset_cb = on_reset;

    ESP_LOGI(TAG, "Initializing GAP and GATT services...");
    ble_svc_gap_init();
    ble_svc_gatt_init();

    ESP_LOGI(TAG, "Setting device name...");
    ble_svc_gap_device_name_set("ESP32-S3-Flic");

    ESP_LOGI(TAG, "Loading paired buttons from NVS...");
    load_all_buttons_from_nvs();

    ESP_LOGI(TAG, "Starting NimBLE host task...");
    nimble_port_freertos_init(nimble_host_task);

    disc_params.filter_duplicates = 0;
    disc_params.passive = 0;
    disc_params.itvl = BLE_GAP_SCAN_ITVL_MS(50);
    disc_params.window = BLE_GAP_SCAN_WIN_MS(30);
    disc_params.filter_policy = BLE_HCI_SCAN_FILT_NO_WL;
    disc_params.limited = 0;

    ESP_LOGI(TAG, "Flic2 ESP32 initialized (NimBLE) - waiting for sync...");

    start_reconnect_timer();

    ESP_LOGI(TAG, "Flic2 ESP32 initialized with reconnection support");
    return ESP_OK;
}

esp_err_t flic2_esp32_start_scan(void) {
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "Starting BLE scan...");
    ESP_LOGI(TAG, "Scan params: itvl=%d, window=%d", disc_params.itvl, disc_params.window);

    print_connection_status();

    int rc = ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &disc_params, gap_event_cb, NULL);

    if (rc != 0) {
        ESP_LOGE(TAG, "Start scanning ERROR: %d", rc);
        ESP_LOGE(TAG, "========================================");
        return ESP_FAIL;
    }

    scanning = true;
    last_scan_time = esp_timer_get_time() / 1000;
    ESP_LOGI(TAG, "BLE scanning started successfully");
    ESP_LOGI(TAG, "========================================");
    return ESP_OK;
}

esp_err_t flic2_esp32_stop_scan(void) {
    int rc = ble_gap_disc_cancel();
    if (rc == 0) {
        scanning = false;
    }
    return (rc == 0) ? ESP_OK : ESP_FAIL;
}

void flic2_esp32_deinit(void) {
    ble_gap_disc_cancel();
    nimble_port_stop();
    nimble_port_deinit();
}