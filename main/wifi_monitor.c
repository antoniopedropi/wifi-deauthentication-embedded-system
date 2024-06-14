#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"
#include "cJSON.h"
#include <time.h>

#define TAG "wifi_ble_sniffer"
#define DEVICE_NAME "ESP32_BLE_Advertiser"
#define WIFI_PKT_MGMT 0
#define DEAUTH 0x0C

static char ble_adv_message[100] = "no_attacks_found";
static int adv_count = 0;

static esp_ble_adv_params_t adv_params = {
    .adv_int_min = 0x2000,  // Min interval in units of 0.625ms, close to 5 seconds
    .adv_int_max = 0x4000,  // Max interval in units of 0.625ms, 10.24 seconds
    .adv_type = ADV_TYPE_IND,
    .own_addr_type = BLE_ADDR_TYPE_PUBLIC,
    .channel_map = ADV_CHNL_ALL,
    .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

void update_ble_adv_data(const char* message) {
    uint8_t adv_data[31] = {
        0x02, 0x01, 0x06,  // Flags: General Discoverable Mode, BR/EDR Not Supported
    };
    size_t msg_len = strlen(message);
    if (msg_len > 25) msg_len = 25;  // Limit to 25 bytes to fit in BLE advertisement data

    adv_data[3] = msg_len + 1;  // Length of the custom data (including type)
    adv_data[4] = 0xFF;         // Type: Manufacturer Specific Data
    memcpy(&adv_data[5], message, msg_len);

    esp_ble_adv_data_t adv_data_struct = {
        .set_scan_rsp = false,
        .include_name = false,
        .include_txpower = false,
        .min_interval = 0x0020,
        .max_interval = 0x0040,
        .appearance = 0x00,
        .manufacturer_len = sizeof(adv_data),
        .p_manufacturer_data = adv_data,
        .service_data_len = 0,
        .p_service_data = NULL,
        .service_uuid_len = 0,
        .p_service_uuid = NULL,
        .flag = (ESP_BLE_ADV_FLAG_GEN_DISC | ESP_BLE_ADV_FLAG_BREDR_NOT_SPT),
    };

    esp_ble_gap_config_adv_data(&adv_data_struct);
}

void extract_ssid(const uint8_t *payload, int length, char *ssid) {
    int pos = 36;
    while (pos < length) {
        uint8_t tag_number = payload[pos];
        uint8_t tag_length = payload[pos + 1];
        if (tag_number == 0 && tag_length <= 32) {
            memcpy(ssid, payload + pos + 2, tag_length);
            ssid[tag_length] = '\0';
            return;
        }
        pos += 2 + tag_length;
    }
    strcpy(ssid, "Unknown SSID");
}

static void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t*)buff;
    const wifi_pkt_rx_ctrl_t *rx_ctrl = &ppkt->rx_ctrl;

    if (type == WIFI_PKT_MGMT) {
        uint8_t* payload = ppkt->payload;
        uint16_t frame_ctrl = payload[0] | (payload[1] << 8);
        uint8_t subtype = (frame_ctrl & 0xF0) >> 4;

        if (subtype == DEAUTH) {
            ESP_LOGI(TAG, "Deauthentication frame detected!");

            char mac_addr[18];
            snprintf(mac_addr, sizeof(mac_addr), "%02x:%02x:%02x:%02x:%02x:%02x",
                     payload[10], payload[11], payload[12], payload[13], payload[14], payload[15]);
            ESP_LOGI(TAG, "Origin MAC address: %s", mac_addr);

            time_t now = time(NULL);

            char ssid[33];
            extract_ssid(payload, rx_ctrl->sig_len, ssid);

            cJSON *json = cJSON_CreateObject();
            cJSON_AddNumberToObject(json, "detectedAt", now);
            cJSON_AddStringToObject(json, "maliciousMACAddress", mac_addr);
            cJSON_AddStringToObject(json, "attackedSSID", ssid);

            char *json_str = cJSON_PrintUnformatted(json);
            if (json_str != NULL) {
                ESP_LOGI(TAG, "JSON: %s", json_str);
                strncpy(ble_adv_message, json_str, sizeof(ble_adv_message) - 1);
                free(json_str);
            } else {
                ESP_LOGE(TAG, "Failed to create JSON string.");
                strcpy(ble_adv_message, "error_creating_json");
            }

            cJSON_Delete(json);
        }
    }
}

void gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {
    switch (event) {
        case ESP_GAP_BLE_ADV_DATA_SET_COMPLETE_EVT:
            esp_ble_gap_start_advertising(&adv_params);
            break;
        case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
            vTaskDelay(pdMS_TO_TICKS(10000));  // Delay for 10 seconds
            esp_ble_gap_stop_advertising();
            update_ble_adv_data(ble_adv_message);
            break;
        case ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT:
            ESP_LOGI(TAG, "Advertising stopped");
            esp_ble_gap_start_advertising(&adv_params);
            break;
        default:
            break;
    }
}

void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler));

    ESP_LOGI(TAG, "ESP32 WiFi Sniffer Initialized");

    ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));
    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_bt_controller_init(&bt_cfg));
    ESP_ERROR_CHECK(esp_bt_controller_enable(ESP_BT_MODE_BLE));
    ESP_ERROR_CHECK(esp_bluedroid_init());
    ESP_ERROR_CHECK(esp_bluedroid_enable());
    ESP_ERROR_CHECK(esp_ble_gap_register_callback(gap_event_handler));
    ESP_ERROR_CHECK(esp_ble_gap_set_device_name(DEVICE_NAME));

    update_ble_adv_data(ble_adv_message);
}
