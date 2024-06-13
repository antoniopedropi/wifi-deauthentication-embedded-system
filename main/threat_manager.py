import serial
import json
import re
import time
import apprise
from datetime import datetime

serial_port = '/dev/serial0'
baud_rate = 115200
timeout = 2

apobj = apprise.Apprise()
webhook_id = '1250087491470495865'
webhook_token = 'hVA6bs0qc3onqEtAsKOQ73skemPxzGweFOXoTHkuhkPGHlGrKLyGH9UVRxLUelW_jIPJ'
apobj.add(f'discord://{webhook_id}/{webhook_token}')

def read_json_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return [json.loads(line) for line in file]
    except FileNotFoundError:
        print(f"{file_path} not found.")
        return []

def receive_serial():
    while True:
        try:
            with serial.Serial(serial_port, baud_rate, timeout=timeout) as ser:
                ser.flushInput()
                print(f"Listening on {serial_port} at {baud_rate} baud rate.")
                while True:
                    try:
                        if ser.in_waiting > 0:
                            line = ser.readline()
                            try:
                                decoded_line = line.decode('utf-8').strip()
                                print("Received:", decoded_line)

                                if not decoded_line.startswith('SSID:'):
                                    if decoded_line.startswith('SID:'):
                                        decoded_line = 'S' + decoded_line
                                    elif decoded_line.startswith('ID:'):
                                        decoded_line = 'SS' + decoded_line

                                match = re.match(r'SSID: (.*?), BSSID: (.*?), RSSI: (.*)', decoded_line)
                                if match:
                                    ssid = match.group(1)
                                    bssid = match.group(2)
                                    rssi = match.group(3)

                                    data = {
                                        "SSID": ssid,
                                        "BSSID": bssid,
                                        "RSSI": rssi
                                    }

                                    with open('captured_aps.json', 'a') as file:
                                        file.write(json.dumps(data) + '\n')
                                    print("Data written to captured_aps.json in JSON format.")

                            except UnicodeDecodeError:
                                print(f"Received (raw bytes): {line}")
                    except Exception as e:
                        print(f"Error reading line: {e}")
                        ser.flushInput()
                        time.sleep(1)
        except serial.SerialException as e:
            print(f"Serial communication error: {e}")
            time.sleep(5)
        except KeyboardInterrupt:
            print("Exiting...")
            break

def receive_bluetooth():
    print("Receive via bluetooth!") 

def send_discord_notification(title, body):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    message = f"{body}\nTimestamp: {timestamp}"
    apobj.notify(
        body=message,
        title=title
    )

if __name__ == '__main__':
    while True:
        legitimate_aps = read_json_file('legitimate_aps.json')
        captured_aps = read_json_file('captured_aps.json')

        for cap_ap in captured_aps:
            for leg_ap in legitimate_aps:
                if cap_ap['SSID'] == leg_ap['SSID'] and cap_ap['BSSID'] != leg_ap['BSSID']:
                    print(f"Captured AP with SSID {cap_ap['SSID']} has different MAC address {cap_ap['BSSID']} compared to legitimate AP.")
                    send_discord_notification('First Alert', 'Captured AP and legitimate AP with different MAC addresses') # first alert

        if True: # Replace this with the receiving of a new bluetooth with a deauth attack
            try:
                with open('deauth_attack.json', 'r') as file:
                    deauth_attack = json.load(file)
                    send_discord_notification('Deauth attack', json.dumps(deauth_attack))
            except FileNotFoundError:
                print("deauth_attack.json not found.")

        time.sleep(10)
