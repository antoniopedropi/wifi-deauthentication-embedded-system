#include <stdio.h>
#include <string.h>
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "cJSON.h"
#include <time.h> // for getting the current time

#define TAG "wifi_sniffer"

// WiFi packet types
#define WIFI_PKT_MGMT 0

// WiFi management frame subtypes
#define BEACON 0x08
#define PROBE_REQ 0x04
#define PROBE_RESP 0x05
#define ASSOC_REQ 0x00
#define REASSOC_REQ 0x02
#define DEAUTH 0x0C  // Deauthentication frame subtype

// Function to base64 encode
char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length) {
    static const char encoding_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static const char padding_char = '=';
    *output_length = 4 * ((input_length + 2) / 3);
    char *encoded_data = malloc(*output_length + 1);
    if (encoded_data == NULL) return NULL;

    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (size_t i = 0; i < 3 - input_length % 3; i++)
        encoded_data[*output_length - 1 - i] = padding_char;
    
    encoded_data[*output_length] = '\0';
    return encoded_data;
}

// Function to extract SSID from a management frame
void extract_ssid(const uint8_t *payload, int length, char *ssid) {
    int pos = 36; // Start after the fixed fields
    while (pos < length) {
        uint8_t tag_number = payload[pos];
        uint8_t tag_length = payload[pos + 1];
        if (tag_number == 0 && tag_length <= 32) { // SSID tag number is 0
            memcpy(ssid, payload + pos + 2, tag_length);
            ssid[tag_length] = '\0';
            return;
        }
        pos += 2 + tag_length;
    }
    strcpy(ssid, "Unknown SSID");
}

// WiFi promiscuous mode callback
static void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t*)buff;
    const wifi_pkt_rx_ctrl_t *rx_ctrl = &ppkt->rx_ctrl;

    // Only process management frames
    if (type == WIFI_PKT_MGMT) {
        uint8_t* payload = ppkt->payload;
        uint16_t frame_ctrl = payload[0] | (payload[1] << 8);
        uint8_t subtype = (frame_ctrl & 0xF0) >> 4;

        // If packet is a deauthentication frame
        if (subtype == DEAUTH) {
            ESP_LOGI(TAG, "Deauthentication frame detected!");

            // Print origin MAC address
            char mac_addr[18];
            snprintf(mac_addr, sizeof(mac_addr), "%02x:%02x:%02x:%02x:%02x:%02x",
                     payload[10], payload[11], payload[12], payload[13], payload[14], payload[15]);
            ESP_LOGI(TAG, "Origin MAC address: %s", mac_addr);

            // Get the current time
            time_t now = time(NULL);

            // Extract the attacked SSID if available
            char ssid[33];
            extract_ssid(payload, rx_ctrl->sig_len, ssid);

            // Create JSON object
            cJSON *json = cJSON_CreateObject();
            cJSON_AddNumberToObject(json, "detectedAt", now);
            cJSON_AddStringToObject(json, "maliciousMACAddress", mac_addr);
            cJSON_AddStringToObject(json, "attackedSSID", ssid);

            // Convert JSON to string
            char *json_str = cJSON_PrintUnformatted(json);
            size_t output_length;
            char *base64_str = base64_encode((const unsigned char *)json_str, strlen(json_str), &output_length);

            if (base64_str != NULL) {
                ESP_LOGI(TAG, "Base64 Encoded JSON: %s", base64_str);
                free(base64_str);
            } else {
                ESP_LOGE(TAG, "Failed to encode JSON to Base64.");
            }

            free(json_str);
            cJSON_Delete(json);
        }
    }
}

void app_main(void) {
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Initialize WiFi
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler));

    ESP_LOGI(TAG, "ESP32 WiFi Sniffer Initialized");
}
