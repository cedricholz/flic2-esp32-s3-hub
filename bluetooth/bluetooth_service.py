import asyncio
import time
from datetime import datetime
from pathlib import Path

import aiohttp
from aiohttp import web, web_runner, ClientSession, ClientTimeout
from zeroconf import ServiceInfo, Zeroconf

from bluetooth.bluetooth_service_cleanup import BlueToothServiceCleanup
from bluetooth.bluetooth_service_flash import BluetoothServiceFlash
from config import ROOT_DIR
from log.log import logger as base_logger

logger = base_logger.getChild("BT")


class BluetoothService(BlueToothServiceCleanup, BluetoothServiceFlash):

    def __init__(self, port=5000, service_name="flic-ble-server"):
        self.port = port
        self.service_name = service_name
        self.app = None
        self.runner = None
        self.site = None
        self.zeroconf = None
        self.service_info = None
        self.firmware_path = f"{ROOT_DIR}/firmware/esp32-flic-project/build/esp32-flic.bin"
        self.version_file = f"{ROOT_DIR}/firmware/esp32-flic-project/build/firmware_version.json"

        self.known_devices = set()
        self.known_usb_devices = set()
        self.flash_lock = asyncio.Lock()
        self.devices_being_flashed = set()
        self.usb_monitor_task = None

        self.esp32_devices = {}
        self.last_heartbeat = {}

    def _start_mdns_service_sync(self):
        import socket

        local_ip = None

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                logger.info(f"Detected local IP: {local_ip}")
        except Exception as e:
            logger.warning(f"Failed to get local IP: {e}")

        if not local_ip:
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
            except Exception:
                local_ip = "127.0.0.1"

        self.zeroconf = Zeroconf()
        service_type = "_http._tcp.local."
        service_name = f"{self.service_name}.{service_type}"

        self.service_info = ServiceInfo(
            service_type,
            service_name,
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties={"service": "flic-bluetooth", "version": "1.0"},
        )
        self.zeroconf.register_service(self.service_info)
        logger.info(f"mDNS service registered: {service_name} at {local_ip}:{self.port}")

    async def _start_mdns_service(self):
        try:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                await asyncio.get_event_loop().run_in_executor(
                    executor, self._start_mdns_service_sync
                )
        except Exception as e:
            logger.error(f"Failed to start mDNS service: {e}")

    async def handle_heartbeat(self, request):
        try:
            data = await request.json()
            mac_address = data.get("mac_address")
            ip_address = data.get("ip_address")
            firmware_version = data.get("firmware_version", "unknown")
            pairing_mode = data.get("pairing_mode", False)
            paired_button_macs = data.get("paired_button_macs", [])

            if mac_address:
                if mac_address not in self.esp32_devices:
                    self.esp32_devices[mac_address] = {}

                self.esp32_devices[mac_address].update({
                    "ip_address": ip_address,
                    "firmware_version": firmware_version,
                    "pairing_mode": pairing_mode,
                    "last_seen": datetime.now().isoformat(),
                    "paired_button_macs": paired_button_macs,
                })
                self.last_heartbeat[mac_address] = datetime.now()
                self.known_devices.add(mac_address)

                button_count = len(paired_button_macs)
                logger.debug(
                    f"Heartbeat: {mac_address} | {ip_address} | fw:{firmware_version} | buttons:{button_count}")

            return web.json_response({"status": "ok"})
        except Exception as e:
            logger.error(f"Error processing heartbeat: {e}")
            return web.json_response({"status": "error", "message": str(e)}, status=500)

    async def handle_button_press(self, request):
        data = await request.json()
        if data.get("type") != "button_event":
            return web.json_response({"status": "ignored"})

        button_mac = data.get("button_mac")
        event_type = data.get("event_type", "click")
        esp32_mac = data.get("esp32_mac")
        battery_percentage = data.get("battery_percentage")

        logger.info(
            f"Button press: {button_mac} | {event_type} | battery:{battery_percentage}% | controller:{esp32_mac}")

        return web.json_response({"status": "ok"})

    async def handle_flic_pairing(self, request):
        data = await request.json()
        button_mac = data.get("button_mac")
        result = data.get("result")
        esp32_mac = data.get("esp32_mac")

        logger.info(f"Pairing result: {button_mac} | {result} | controller:{esp32_mac}")

        return web.json_response({"status": "ok"})

    async def handle_health_check(self, request):
        return web.json_response({
            "status": "healthy",
            "service": "flic-bluetooth",
            "timestamp": time.time(),
            "esp32_devices": len(self.esp32_devices),
        })

    async def handle_device_discovery(self, request):
        try:
            data = await request.json()
            mac_address = data.get("mac_address")
            ip_address = data.get("ip_address")
            firmware_version = data.get("firmware_version", "unknown")

            if mac_address not in self.known_devices:
                logger.info(f"New ESP32 discovered: {mac_address} at {ip_address} (fw: {firmware_version})")
                self.known_devices.add(mac_address)

                if mac_address not in self.esp32_devices:
                    self.esp32_devices[mac_address] = {}

                self.esp32_devices[mac_address].update({
                    "ip_address": ip_address,
                    "firmware_version": firmware_version,
                    "last_seen": datetime.now().isoformat(),
                })

            return web.json_response({"status": "registered"})
        except Exception as e:
            logger.error(f"Error handling device discovery: {e}")
            return web.json_response({"status": "error"}, status=500)

    async def handle_esp32_status(self, request):
        now = datetime.now()
        device_status = {}

        for mac, info in self.esp32_devices.items():
            last_hb = self.last_heartbeat.get(mac)
            if last_hb:
                seconds_since = (now - last_hb).total_seconds()
                is_online = seconds_since < 60
            else:
                is_online = False
                seconds_since = None

            device_status[mac] = {
                **info,
                "is_online": is_online,
                "seconds_since_heartbeat": seconds_since,
            }

        return web.json_response({
            "status": "ok",
            "devices": device_status,
            "total_devices": len(device_status),
        })

    async def handle_enable_pairing(self, request):
        try:
            data = await request.json()
            mac_address = data.get("mac_address")

            if not mac_address:
                return web.json_response({"status": "error", "message": "mac_address required"}, status=400)

            device = self.esp32_devices.get(mac_address)
            if not device:
                return web.json_response({"status": "error", "message": "device not found"}, status=404)

            if not self._is_device_online(mac_address):
                return web.json_response({"status": "error", "message": "device offline"}, status=503)

            if await self._send_command_to_esp32(device["ip_address"], "/enable-pairing"):
                logger.info(f"Enabled pairing on {mac_address}")
                return web.json_response({"status": "ok"})
            else:
                return web.json_response({"status": "error", "message": "command failed"}, status=500)

        except Exception as e:
            logger.error(f"Error enabling pairing: {e}")
            return web.json_response({"status": "error", "message": str(e)}, status=500)

    async def handle_disable_pairing(self, request):
        try:
            data = await request.json()
            mac_address = data.get("mac_address")

            if not mac_address:
                return web.json_response({"status": "error", "message": "mac_address required"}, status=400)

            device = self.esp32_devices.get(mac_address)
            if not device:
                return web.json_response({"status": "error", "message": "device not found"}, status=404)

            if await self._send_command_to_esp32(device["ip_address"], "/disable-pairing"):
                logger.info(f"Disabled pairing on {mac_address}")
                return web.json_response({"status": "ok"})
            else:
                return web.json_response({"status": "error", "message": "command failed"}, status=500)

        except Exception as e:
            logger.error(f"Error disabling pairing: {e}")
            return web.json_response({"status": "error", "message": str(e)}, status=500)

    def _is_device_online(self, mac):
        last_hb = self.last_heartbeat.get(mac)
        if not last_hb:
            return False
        return (datetime.now() - last_hb).total_seconds() < 60

    async def _send_command_to_esp32(self, ip_address, endpoint):
        try:
            url = f"http://{ip_address}{endpoint}"
            timeout = aiohttp.ClientTimeout(total=5)

            async with ClientSession(timeout=timeout) as session:
                async with session.post(url) as response:
                    return response.status == 200
        except Exception as e:
            logger.error(f"Failed to send command to ESP32 at {ip_address}: {e}")
            return False

    async def handle_firmware_download(self, request):
        try:
            fw_path = Path(self.firmware_path)
            if not fw_path.exists():
                return web.Response(status=404, text="Firmware not found")
            return web.FileResponse(fw_path)
        except Exception as e:
            logger.error(f"Error serving firmware: {e}")
            return web.Response(status=500, text="Internal error")

    async def run(self):
        try:
            port_ok = await self._ensure_port_free_before_start()
            if not port_ok:
                logger.error(f"Could not free port {self.port}")
                return

            self.app = web.Application()
            self.app.router.add_get("/health", self.handle_health_check)
            self.app.router.add_get("/", self.handle_health_check)
            self.app.router.add_post("/button-press", self.handle_button_press)
            self.app.router.add_post("/device-discovery", self.handle_device_discovery)
            self.app.router.add_post("/heartbeat", self.handle_heartbeat)
            self.app.router.add_post("/flic-pairing", self.handle_flic_pairing)
            self.app.router.add_get("/esp32-status", self.handle_esp32_status)
            self.app.router.add_post("/enable-pairing", self.handle_enable_pairing)
            self.app.router.add_post("/disable-pairing", self.handle_disable_pairing)
            self.app.router.add_post("/force-usb-flash", self.handle_force_usb_flash)
            self.app.router.add_post("/trigger-ota-updates", self.handle_trigger_ota_updates)
            self.app.router.add_get("/firmware/esp32-flic.bin", self.handle_firmware_download)
            self.app.router.add_static("/firmware/", str(Path(self.firmware_path).parent), name="firmware")

            self.runner = web_runner.AppRunner(self.app, access_log=None)
            await self.runner.setup()

            try:
                self.site = web_runner.TCPSite(self.runner, host="0.0.0.0", port=self.port, reuse_port=True)
            except TypeError:
                self.site = web_runner.TCPSite(self.runner, host="0.0.0.0", port=self.port)

            await self.site.start()
            logger.info(f"Server listening on 0.0.0.0:{self.port}")

            await self._start_mdns_service()

            self.usb_monitor_task = asyncio.create_task(self._monitor_usb_devices())
            self.ota_check_task = asyncio.create_task(self._periodic_ota_check())

            logger.info("Flic hub ready")

            while True:
                await asyncio.sleep(1)

        except asyncio.CancelledError:
            logger.info("Service cancelled")
        except Exception as e:
            logger.error(f"Error in run: {e}")
            raise

    async def _periodic_ota_check(self):
        while True:
            try:
                await asyncio.sleep(60)
                await self.check_for_ota_updates()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"OTA check error: {e}")
                await asyncio.sleep(60)
