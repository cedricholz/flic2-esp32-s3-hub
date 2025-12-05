#ifndef FLIC2_ESP32_H
#define FLIC2_ESP32_H
typedef struct cJSON cJSON;

#include "../../../flic2lib-c-module-main/flic2.h"
#include "esp_timer.h"
#include <stdint.h>
#include <stdbool.h>

#define MAX_FLIC_BUTTONS 9

int flic2_esp32_get_paired_count(void);

esp_err_t flic2_esp32_unpair_button(const char* mac_address);

#ifdef __cplusplus
extern "C" {
#endif

int flic2_count_paired_buttons_in_nvs(void);

#ifdef __cplusplus
}
#endif

cJSON* flic2_esp32_get_paired_buttons_json(void);

typedef struct {
    char mac_address[18];
    uint16_t conn_handle;
    uint8_t remote_bda[6];
    bool connected;
    uint16_t write_handle;
    uint16_t notify_handle;
    struct Flic2Button button;
    esp_timer_handle_t timer_handle;
    uint16_t service_start_handle;
    uint16_t service_end_handle;
} flic_device_t;

typedef void (*flic_event_callback_t)(const char* button_mac, int event_type, int battery_mv);

esp_err_t flic2_esp32_init(flic_event_callback_t callback);
esp_err_t flic2_esp32_start_scan(void);
esp_err_t flic2_esp32_stop_scan(void);
void flic2_esp32_deinit(void);

#endif