import json
import os
from bluepy.btle import Scanner, DefaultDelegate

class ScanDelegate(DefaultDelegate):
    def __init__(self):
        DefaultDelegate.__init__(self)

    def handleDiscovery(self, dev, isNewDev, isNewData):
        if isNewDev:
            print(f"Discovered device {dev.addr}")
        elif isNewData:
            print(f"Received new data from {dev.addr}")

def is_deauth_attack_message(message):
    try:
        data = json.loads(message)
        required_keys = ["detectedAt", "maliciousMACAddress", "attackedSSID"]
        return all(key in data for key in required_keys)
    except json.JSONDecodeError:
        return False

def main():
    scanner = Scanner().withDelegate(ScanDelegate())
    print("Starting BLE scan...")

    while True:
        devices = scanner.scan(10.0)  # Scan for 10 seconds
        for dev in devices:
            for (adtype, desc, value) in dev.getScanData():
                if desc == "Manufacturer" and len(value) > 5:
                    adv_data = bytes.fromhex(value).decode('utf-8', errors='ignore')
                    print(f"Advertisement data: {adv_data}")

                    if is_deauth_attack_message(adv_data):
                        print("Deauthentication attack detected!")
                        attack_data = json.loads(adv_data)
                        with open("deauth_attack.json", "w") as f:
                            json.dump(attack_data, f, indent=4)
                        print(f"Attack data saved to deauth_attack.json")

if __name__ == "__main__":
    main()

