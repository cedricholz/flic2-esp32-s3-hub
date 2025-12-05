# Flic2 ESP32-S3 Hub

A self-hosted Flic 2 button hub using ESP32-S3 microcontrollers. Run the server on a Raspberry Pi or mini PC to handle button pairing, click events, and device management over your local network.

This project provides an open-source alternative for managing Flic 2 Bluetooth buttons without relying on Flic's official hub or cloud services.

## Features

- **Device Discovery**: ESP32-S3 controllers automatically discover the server via mDNS
- **Button Pairing**: Pair up to 9 Flic 2 buttons per ESP32-S3 controller
- **Unlimited Controllers**: Run as many ESP32-S3 controllers as you need on your network
- **Click Events**: Receive single click, double click, and hold events
- **OTA Updates**: Push firmware updates to all ESP32 devices over the network automatically
- **USB Flashing**: Automatically flash new ESP32 devices when connected via USB

## Hardware

### Server
Any Linux machine works - Raspberry Pi, mini PC, or a full server.

### ESP32-S3 Controller
This project uses the [Waveshare ESP32-S3-ETH](https://www.waveshare.com/wiki/ESP32-S3-ETH) development board with PoE module:

- ESP32-S3R8 chip with dual-core 240MHz processor
- 8MB PSRAM, 16MB Flash
- W5500 Ethernet chip (10/100Mbps)
- PoE support - single cable for power and network
- Wi-Fi and Bluetooth 5 LE

The PoE version is recommended as it simplifies deployment - just run an Ethernet cable to each controller.

**Note**: The firmware uses NimBLE and only supports Bluetooth Low Energy (BLE), not classic Bluetooth.

### Flic 2 Buttons
Standard [Flic 2 buttons](https://flic.io/flic2).

## Architecture
```
┌─────────────┐     Ethernet      ┌─────────────┐
│   Server    │◄─────────────────►│  ESP32-S3   │◄──── BLE ────► Flic 2 Buttons (up to 9)
│  (Python)   │                   │ Controller  │
└─────────────┘                   └─────────────┘
       │                                 
       │                          ┌─────────────┐
       │◄────────────────────────►│  ESP32-S3   │◄──── BLE ────► Flic 2 Buttons (up to 9)
       │                          │ Controller  │
       │                          └─────────────┘
       │
       │                          (... unlimited controllers)
       ▼
  Your Application
  (webhooks, home automation, etc.)
```

The ESP32-S3 handles BLE communication with Flic buttons and forwards events to the Python server over Ethernet. The server manages device state, coordinates pairing, and can trigger actions based on button presses.

## Credits

This project uses the [flic2lib-c](https://github.com/50ButtonsEach/flic2lib-c-module) library from Shortcut Labs for Flic 2 protocol implementation.

## Server Setup

### Prerequisites

Install Python 3.10+ and Poetry:
```bash
# Install Python 3.10 (Ubuntu/Debian)
sudo apt update
sudo apt install python3.10 python3.10-dev python3-pip

# Install Poetry
curl -sSL https://install.python-poetry.org | python3 -
```

Add Poetry to your PATH (add to `~/.bashrc`):
```bash
export PATH="$HOME/.local/bin:$PATH"
```

### Installation

Clone the repository:
```bash
git clone https://github.com/cedricholz/flic2-esp32-s3-hub.git
cd flic2-esp32-s3-hub
```

Install dependencies:
```bash
poetry install
```

### Running
```bash
poetry run python main.py
```

The server starts on port 5000 by default.

### Docker Setup (Alternative)

Build and run with Docker:
```bash
docker build -t flic2-hub .
docker run --rm --network host --privileged -v /dev:/dev flic2-hub
```

Or use the setup script to install as a systemd service:
```bash
chmod +x setup.sh
./setup.sh
```

## ESP32-S3 Firmware

### Pre-built Firmware

The repository includes pre-built firmware in `firmware/esp32-flic-project/build/`. You can flash this directly without needing to build from source.

### Flashing

#### Automatic USB Flashing

1. Make sure the server is running
2. Connect the ESP32-S3 via USB to the server
3. Watch the server logs - the hub will automatically detect and flash the device
```bash
# Follow the logs to see flashing progress
poetry run python main.py
```

**Important**: The ESP32 will only be auto-flashed if you plug it in while the service is running. Check the logs to confirm when flashing is complete before unplugging.

#### Manual USB Flash
```bash
python -m esptool --chip esp32s3 --port /dev/ttyACM0 --baud 460800 \
  write_flash --flash-mode dio --flash-freq 80m --flash-size 16MB -z \
  0x0 firmware/esp32-flic-project/build/bootloader/bootloader.bin \
  0x8000 firmware/esp32-flic-project/build/partition_table/partition-table.bin \
  0x10000 firmware/esp32-flic-project/build/esp32-flic.bin
```

#### OTA Updates

Once ESP32 devices are deployed on your network, firmware updates are pushed automatically. The server checks for version mismatches and triggers OTA updates - no need to physically access the devices.

Manually trigger an OTA update check:
```bash
curl -X POST http://localhost:5000/trigger-ota-updates
```

### Building Firmware (Optional)

Only needed if you want to modify the firmware.

#### Prerequisites

Download and install [ESP-IDF 5.5](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/get-started/index.html).

#### Building

Open the ESP-IDF 5.5 terminal and run the build script:
```powershell
cd firmware/esp32-flic-project
.\reset_build.ps1
```

This script cleans the build directory, sets the target to ESP32-S3, and compiles the firmware.

Alternatively, run the commands manually:
```bash
cd firmware/esp32-flic-project
idf.py set-target esp32s3
idf.py build
```

The compiled firmware will be in `firmware/esp32-flic-project/build/`.

If you clone this repo and accidentally delete the build files, you'll have to re-add them to git:
```bash
git add -f firmware/esp32-flic-project/build/bootloader/bootloader.bin
git add -f firmware/esp32-flic-project/build/bootloader/bootloader.bin
git add -f firmware/esp32-flic-project/build/esp32-flic.bin
git add -f firmware/esp32-flic-project/build/firmware_version.json
git add -f firmware/esp32-flic-project/build/flasher_args.json
git add -f firmware/esp32-flic-project/build/partition_table/partition-table.bin
```

### Monitoring ESP32 Logs
Stop the service, plug in the ESP32 via USB so it doesn't re-flash, start the server, then run:
```bash
python -m serial.tools.miniterm /dev/ttyACM0 115200
```
**Note**: Replace `/dev/ttyACM0` with the correct port for your ESP32 device. It will be displayed in the server logs when the device connects.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/esp32-status` | List all ESP32 devices and their status |
| POST | `/heartbeat` | ESP32 heartbeat (called by firmware) |
| POST | `/device-discovery` | ESP32 registration (called by firmware) |
| POST | `/button-press` | Button event (called by firmware) |
| POST | `/flic-pairing` | Pairing result (called by firmware) |
| POST | `/enable-pairing` | Enable pairing mode on an ESP32 |
| POST | `/disable-pairing` | Disable pairing mode |
| POST | `/force-usb-flash` | Force flash a USB-connected ESP32 |
| POST | `/trigger-ota-updates` | Trigger OTA update check |
| GET | `/firmware/esp32-flic.bin` | Download firmware (for OTA) |

## Usage

### Pairing a Flic Button

1. Enable pairing mode on an ESP32 controller:
```bash
curl -X POST http://localhost:5000/enable-pairing \
  -H "Content-Type: application/json" \
  -d '{"mac_address": "aa:bb:cc:dd:ee:ff"}'
```

2. Hold the Flic button for 7+ seconds until it rapidly flashes

3. The button will pair with the ESP32 and events will be forwarded to the server

Each ESP32 can pair with up to 9 Flic buttons. Deploy additional ESP32 controllers for more buttons.

### Handling Button Events

Button presses are logged by default. To integrate with your application, modify the `handle_button_press` method in `bluetooth/bluetooth_service.py`:
```python
async def handle_button_press(self, request):
    data = await request.json()
    button_mac = data.get("button_mac")
    event_type = data.get("event_type")  # "click", "double_click", or "hold"
    battery_percentage = data.get("battery_percentage")
    
    # Add your logic here
    # - Call a webhook
    # - Trigger home automation
    # - Control smart devices
    
    return web.json_response({"status": "ok"})
```

### Force Flash an ESP32

If you need to manually flash a specific USB device:
```bash
curl -X POST http://localhost:5000/force-usb-flash \
  -H "Content-Type: application/json" \
  -d '{"device_port": "/dev/ttyACM0"}'
```

## Troubleshooting

### ESP32 not discovered
- Ensure the ESP32 and server are on the same network
- Check that mDNS is working: `avahi-browse -a`
- Verify the ESP32 has an IP address (check serial logs)

### Pairing fails
- Make sure the Flic button is in pairing mode (rapid flashing)
- Try holding the button longer (7+ seconds)
- Check ESP32 logs for errors
- Ensure you haven't exceeded 9 buttons on that controller

### OTA update fails
- Verify firmware file exists at `firmware/esp32-flic-project/build/esp32-flic.bin`
- Check network connectivity between server and ESP32
- Review server logs for HTTP errors

### Erase ESP32 Flash
If the ESP32 is in a bad state:
```bash
python -m esptool --chip esp32s3 --port /dev/ttyACM0 --baud 460800 erase_flash
```

Then reflash the firmware.

## License

GPL-3.0 License - see LICENSE file for details.

This project uses [flic2lib-c](https://github.com/50ButtonsEach/flic2lib-c-module) which is licensed under GPL-3.0.