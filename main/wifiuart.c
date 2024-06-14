#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "driver/uart.h"
#include "esp_system.h"
#include "driver/gpio.h"
#include "mbedtls/base64.h"


#ifndef CONFIG_EXAMPLE_SCAN_LIST_SIZE
#define CONFIG_EXAMPLE_SCAN_LIST_SIZE 10
#endif

#define DEFAULT_SCAN_LIST_SIZE CONFIG_EXAMPLE_SCAN_LIST_SIZE


static const char *TAG = "scan_uart";
#define DEFAULT_SCAN_LIST_SIZE CONFIG_EXAMPLE_SCAN_LIST_SIZE

#define TXD_PIN (GPIO_NUM_17)
#define RXD_PIN (GPIO_NUM_16)
#define RX_BUF_SIZE 1024
#define UART_NUM UART_NUM_1

//115200
//9600
void init_uart(void) {
    const uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    uart_driver_install(UART_NUM, RX_BUF_SIZE * 2, 0, 0, NULL, 0);
    uart_param_config(UART_NUM, &uart_config);
    uart_set_pin(UART_NUM, TXD_PIN, RXD_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
}

int send_data(const char* data) {
     const int len = strlen(data);
     const int txBytes = uart_write_bytes(UART_NUM, data, len);
     ESP_LOGI(TAG, "Wrote %d bytes", txBytes);
     return txBytes;
}

/*
int send_data(const char* data) {
    size_t output_len;
    unsigned char base64_output[512]; // Ensure this is large enough for base64 encoding

    // Encode the data to Base64
    int ret = mbedtls_base64_encode(base64_output, sizeof(base64_output), &output_len, (const unsigned char *)data, strlen(data));
    if (ret != 0) {
        ESP_LOGE(TAG, "Base64 encoding failed");
        return -1;
    }

    const int txBytes = uart_write_bytes(UART_NUM, (const char*)base64_output, output_len);
    ESP_LOGI(TAG, "Wrote %d bytes", txBytes);
    return txBytes;
}
*/


static void tx_task(void *arg) {
    while (1) {
        // Placeholder for sending periodic data, if needed
        vTaskDelay(2000 / portTICK_PERIOD_MS);
    }
}

static void rx_task(void *arg) {
    uint8_t* data = (uint8_t*) malloc(RX_BUF_SIZE + 1);
    while (1) {
        const int rxBytes = uart_read_bytes(UART_NUM, data, RX_BUF_SIZE, 1000 / portTICK_PERIOD_MS);
        if (rxBytes > 0) {
            data[rxBytes] = 0;
            ESP_LOGI(TAG, "Read %d bytes: '%s'", rxBytes, data);
            ESP_LOG_BUFFER_HEXDUMP(TAG, data, rxBytes, ESP_LOG_INFO);
        }
    }
    free(data);
}

static void wifi_scan(void) {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_t *sta_netif = esp_netif_create_default_wifi_sta();
    assert(sta_netif);

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    uint16_t number = DEFAULT_SCAN_LIST_SIZE;
    wifi_ap_record_t ap_info[DEFAULT_SCAN_LIST_SIZE];
    uint16_t ap_count = 0;
    memset(ap_info, 0, sizeof(ap_info));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    esp_wifi_scan_start(NULL, true);

    ESP_LOGI(TAG, "Max AP number ap_info can hold = %u", number);
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&number, ap_info));
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&ap_count));
    ESP_LOGI(TAG, "Total APs scanned = %u, actual AP number ap_info holds = %u", ap_count, number);

    for (int i = 0; i < number; i++) {
        char buffer[256];
        snprintf(buffer, sizeof(buffer), "SSID: %s, BSSID: %02X:%02X:%02X:%02X:%02X:%02X, RSSI: %d\n",
                 ap_info[i].ssid,
                 ap_info[i].bssid[0], ap_info[i].bssid[1], ap_info[i].bssid[2],
                 ap_info[i].bssid[3], ap_info[i].bssid[4], ap_info[i].bssid[5],
                 ap_info[i].rssi);
        send_data(buffer);
        ESP_LOGI(TAG, "SSID: %s, BSSID: %02X:%02X:%02X:%02X:%02X:%02X, RSSI: %d",
                 ap_info[i].ssid,
                 ap_info[i].bssid[0], ap_info[i].bssid[1], ap_info[i].bssid[2],
                 ap_info[i].bssid[3], ap_info[i].bssid[4], ap_info[i].bssid[5],
                 ap_info[i].rssi);
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

    init_uart();

    // Create UART tasks
    xTaskCreate(rx_task, "uart_rx_task", 1024 * 2, NULL, configMAX_PRIORITIES - 1, NULL);
    xTaskCreate(tx_task, "uart_tx_task", 1024 * 2, NULL, configMAX_PRIORITIES - 2, NULL);

    // Perform Wi-Fi scan
    wifi_scan();
}
