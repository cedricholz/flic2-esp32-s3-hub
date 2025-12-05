import asyncio
import json
import os
import sys
from pathlib import Path
import aiohttp
from aiohttp import ClientSession, ClientTimeout
import socket

from log.log import logger as base_logger
from aiohttp import web, web_runner, ClientSession

logger = base_logger.getChild("BT")


class BluetoothServiceFlash:

    def _is_port_free(self, port: int) -> bool:
        """Check if a port is free"""
        import socket

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("0.0.0.0", port))
                return True
        except OSError:
            return False

    def _detect_port_listener_detail(self, port: int):
        """
        Return (has_listener: bool, pids: list[int], diag: str)
        - Detects listeners even when PID is hidden (non-root).
        - Tries: ss, lsof, fuser (without sudo).
        """
        import subprocess, shlex

        diag_lines = []

        # 1) ss (fast, modern)
        try:
            # show TCP listen sockets, no header
            # Some kernels hide pid= unless we are root, but we can still see that something is LISTENing.
            cmd = ["ss", "-H", "-ltnp"]
            res = subprocess.run(
                cmd, capture_output=True, text=True, timeout=3, check=False
            )
            if res.stdout:
                matches = [
                    ln
                    for ln in res.stdout.splitlines()
                    if f":{port} " in ln or ln.rstrip().endswith(f":{port}")
                ]
                if matches:
                    diag_lines.append("ss -ltnp matches:\n" + "\n".join(matches))
                    # Try to extract pid= if present
                    import re

                    pids = []
                    for ln in matches:
                        for m in re.finditer(r"pid=(\d+)", ln):
                            try:
                                pids.append(int(m.group(1)))
                            except ValueError:
                                pass
                    if pids:
                        return True, sorted(set(pids)), "\n".join(diag_lines)
                    else:
                        # Listener present but pid hidden
                        return True, [], "\n".join(diag_lines)
        except Exception as e:
            diag_lines.append(f"ss error: {e}")

        # 2) lsof (may not show PID info for root-owned procs unless run with sudo)
        try:
            cmd = ["lsof", "-nP", "-iTCP", f":{port}", "-sTCP:LISTEN"]
            res = subprocess.run(
                cmd, capture_output=True, text=True, timeout=3, check=False
            )
            if res.returncode == 0 and res.stdout.strip():
                diag_lines.append("lsof output:\n" + res.stdout.strip())
                # Quick PID pull
                cmd2 = ["lsof", "-tiTCP", f":{port}", "-sTCP:LISTEN"]
                res2 = subprocess.run(
                    cmd2, capture_output=True, text=True, timeout=3, check=False
                )
                pids = (
                    [int(x) for x in res2.stdout.split() if x.isdigit()]
                    if (res2.stdout or "")
                    else []
                )
                return True, sorted(set(pids)), "\n".join(diag_lines)
        except Exception as e:
            diag_lines.append(f"lsof error: {e}")

        # 3) fuser (sometimes shows PIDs without root)
        try:
            cmd = ["fuser", "-n", "tcp", str(port)]
            res = subprocess.run(
                cmd, capture_output=True, text=True, timeout=3, check=False
            )
            # fuser prints PIDs to stdout; returncode 0 if any found
            if res.returncode == 0 and res.stdout.strip():
                diag_lines.append("fuser output:\n" + res.stdout.strip())
                import re

                pids = [int(x) for x in re.findall(r"\b(\d+)\b", res.stdout)]
                return True, sorted(set(pids)), "\n".join(diag_lines)
            # Even if returncode != 0, it can print diag to stderr
            if res.stderr.strip():
                diag_lines.append("fuser stderr:\n" + res.stderr.strip())
        except Exception as e:
            diag_lines.append(f"fuser error: {e}")

        # No positive signals from tools
        return False, [], "\n".join(diag_lines)

    def _maybe_sudo_kill_port(self, port: int) -> bool:
        """
        Best-effort non-interactive sudo kill for root-owned listeners.
        - Uses 'sudo -n' so it NEVER prompts. If not allowed, it fails fast.
        Returns True if it *appears* to have succeeded (not guaranteed).
        """
        import subprocess, time

        # Try to list PIDs with sudo
        try:
            res = subprocess.run(
                ["sudo", "-n", "lsof", "-tiTCP", f":{port}", "-sTCP:LISTEN"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                pids = [
                    x for x in res.stdout.strip().splitlines() if x.strip().isdigit()
                ]
                if pids:
                    # Try SIGTERM first
                    subprocess.run(
                        ["sudo", "-n", "kill", "-TERM", *pids], timeout=3, check=False
                    )
                    time.sleep(0.4)
                    # Whatever remains, SIGKILL
                    subprocess.run(
                        ["sudo", "-n", "kill", "-KILL", *pids], timeout=3, check=False
                    )
                    time.sleep(0.4)
                    return True
        except Exception:
            pass

        # Fallback: sudo fuser -k (kills processes using the port)
        try:
            # -k kill, -n tcp namespace
            res = subprocess.run(
                ["sudo", "-n", "fuser", "-k", "-n", "tcp", str(port)],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            # fuser returns 0 on success, 1 on failure, 2 if no access, etc.
            return res.returncode == 0
        except Exception:
            pass

        return False

    def _pids_on_port(self, port: int) -> list[int]:
        """
        Retained for compatibility with prior code paths; now uses _detect_port_listener_detail.
        """
        has_listener, pids, _ = self._detect_port_listener_detail(port)
        return pids if has_listener else []


    def _free_port_best_effort(self, port: int) -> bool:
        import time, os, signal

        if self._is_port_free(port):
            logger.info(f"Port {port} is already free.")
            return True

        has_listener, pids, diag = self._detect_port_listener_detail(port)
        if not has_listener:
            # Could be TIME_WAIT noise; quick re-check.
            logger.warning(
                f"No listeners reported for port {port}, will re-check shortly."
            )
            time.sleep(0.3)
            return self._is_port_free(port)

        if pids:
            my_pid = os.getpid()
            victims = [pid for pid in pids if pid != my_pid]
            if not victims:
                # Only ourselves? Treat as free.
                return True

            logger.warning(f"Port {port} in use by PIDs: {victims}")
            # Graceful then force
            for pid in victims:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                except PermissionError as e:
                    logger.warning(f"Permission error sending SIGTERM to {pid}: {e}")
            time.sleep(0.4)
            for pid in victims:
                try:
                    os.kill(pid, 0)  # still alive?
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except PermissionError as e:
                    logger.warning(f"Permission error sending SIGKILL to {pid}: {e}")
        else:
            # Listener exists but PID is hidden (likely root-owned). Try non-interactive sudo.
            logger.warning(
                "Listener detected on port %s but PIDs are hidden (likely root-owned). "
                "Attempting fast, non-interactive sudo cleanup.",
                port,
            )
            sudo_ok = self._maybe_sudo_kill_port(port)
            if not sudo_ok:
                logger.error(
                    "Non-interactive sudo cleanup failed or is not permitted.\n"
                    "Diagnostic output:\n%s\n"
                    "Next steps (manual):\n"
                    "  sudo lsof -nP -iTCP:%s -sTCP:LISTEN\n"
                    "  sudo ss -ltnp '( sport = :%s )'\n"
                    "  sudo fuser -v -n tcp %s\n"
                    "Then stop/kill the owning service or run: sudo fuser -k -n tcp %s",
                    diag,
                    port,
                    port,
                    port,
                    port,
                )

        # Re-check after attempts
        time.sleep(0.5)
        free = self._is_port_free(port)
        if free:
            logger.info(f"Port {port} freed successfully.")
        else:
            # Include diag to help you see who owns it
            logger.error(
                f"Port {port} still not free. Last diagnostics:\n{diag or '(no diag)'}"
            )
        return free

    async def _ensure_port_free_before_start(self) -> bool:
        """
        Async wrapper; try several times with short pauses.
        """
        import concurrent.futures, asyncio as _asyncio

        retries = 3
        with concurrent.futures.ThreadPoolExecutor() as pool:
            for attempt in range(1, retries + 1):
                ok = await _asyncio.get_event_loop().run_in_executor(
                    pool, self._free_port_best_effort, self.port
                )
                if ok:
                    return True
                logger.warning(
                    "Attempt %d/%d to free port %s failed; retrying...",
                    attempt,
                    retries,
                    self.port,
                )
                await _asyncio.sleep(0.5)
        return False

    async def _probe_usb_device(self, device_port, timeout_seconds=10):
        """
        Try to determine if a USB-connected ESP32 is running valid firmware
        Returns device info dict if successful, None if device doesn't respond
        """
        logger.info(f"Probing USB device {device_port} for firmware status...")

        # Strategy 1: Try to find the device on the network
        # Look for recent ESP32 devices that appeared in our known devices
        for mac, device_info in self.esp32_devices.items():
            if device_info.get("last_seen"):
                from datetime import datetime, timedelta

                try:
                    last_seen = datetime.fromisoformat(device_info["last_seen"])
                    if datetime.now() - last_seen < timedelta(seconds=60):
                        # Recent device - might be our USB-connected one
                        if await self._test_esp32_connection(device_info["ip_address"]):
                            logger.info(
                                f"Found recently connected ESP32 at {device_info['ip_address']}"
                            )
                            return device_info
                except Exception as e:
                    logger.debug(f"Error checking recent device {mac}: {e}")

        # Strategy 2: Wait a bit for the device to connect and send heartbeat
        logger.info(
            f"Waiting up to {timeout_seconds}s for device to connect to network..."
        )
        for attempt in range(timeout_seconds):
            await asyncio.sleep(1)

            # Check if any new devices appeared
            for mac, device_info in self.esp32_devices.items():
                if device_info.get("last_seen"):
                    try:
                        last_seen = datetime.fromisoformat(device_info["last_seen"])
                        if datetime.now() - last_seen < timedelta(seconds=5):
                            logger.info(
                                f"New ESP32 connected: {mac} at {device_info['ip_address']}"
                            )
                            return device_info
                    except Exception:
                        continue

        logger.warning(
            f"USB device {device_port} did not connect to network within {timeout_seconds}s"
        )
        return None

    async def _test_esp32_connection(self, ip_address):
        """Test if ESP32 at given IP is responding"""
        try:
            timeout = ClientTimeout(total=3)
            async with ClientSession(timeout=timeout) as session:
                async with session.get(f"http://{ip_address}/status") as response:
                    return response.status == 200
        except Exception:
            return False

    async def _trigger_ota_update(self, device_ip, device_mac):
        """Trigger OTA update on ESP32 device"""
        logger.info(f"Starting OTA update for {device_mac} at {device_ip}")

        try:
            timeout = ClientTimeout(total=10)
            async with ClientSession(timeout=timeout) as session:
                pi_ip = await self._get_server_ip_address()
                firmware_url = f"http://{pi_ip}:{self.port}/firmware/esp32-flic.bin"

                ota_payload = {
                    "firmware_url": firmware_url,
                    "expected_version": self._get_expected_firmware_version(),
                }

                async with session.post(
                    f"http://{device_ip}/ota-update", json=ota_payload
                ) as response:
                    if response.status == 200:
                        logger.info(f"OTA update initiated for {device_mac}")
                        return True
                    elif response.status == 409:
                        logger.info(f"OTA already in progress for {device_mac}")
                        return True
                    else:
                        logger.error(
                            f"OTA update failed for {device_mac}: HTTP {response.status}"
                        )
                        return False

        except Exception as e:
            logger.error(f"Failed to trigger OTA update for {device_mac}: {e}")
            return False

    async def _get_server_ip_address(self):
        """Get Server's IP address for ESP32 to download firmware from"""
        try:
            # Try to determine Server's IP by connecting outbound
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"  # Fallback

    async def _flash_usb_device_internal(self, device_port):
        try:
            fw_path = Path(self.firmware_path)
            build_dir = fw_path.parent
            bootloader_path = build_dir / "bootloader" / "bootloader.bin"
            partition_path = build_dir / "partition_table" / "partition-table.bin"

            missing = [
                p for p in [bootloader_path, partition_path, fw_path] if not p.exists()
            ]
            if missing:
                for p in missing:
                    logger.error(f"Required image not found: {p}")
                return

            logger.info(f"Flashing ESP32-S3 on {device_port}")
            logger.info(f"Bootloader: {bootloader_path}")
            logger.info(f"Partition : {partition_path}")
            logger.info(f"App       : {fw_path}")

            erase_cmd = [
                sys.executable,
                "-m",
                "esptool",
                "--chip",
                "esp32s3",
                "--port",
                device_port,
                "--baud",
                "460800",
                "erase-flash",
            ]
            logger.info("Erasing flash…")
            logger.debug("Erase command: %s", " ".join(map(str, erase_cmd)))

            try:
                process = await asyncio.create_subprocess_exec(
                    *erase_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=90.0
                )
                if stdout:
                    logger.debug(stdout.decode(errors="ignore"))
                if stderr:
                    logger.debug(stderr.decode(errors="ignore"))
                if process.returncode != 0:
                    logger.error(f"Flash erase failed (rc={process.returncode})")
                    return
                logger.info("Flash erased successfully.")
            except asyncio.TimeoutError:
                logger.error("Flash erase timed out.")
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass
                return

            await asyncio.sleep(2)

            flash_cmd = [
                sys.executable,
                "-m",
                "esptool",
                "--chip",
                "esp32s3",
                "--port",
                device_port,
                "--baud",
                "460800",
                "write-flash",
                "--flash-mode",
                "dio",
                "--flash-freq",
                "80m",
                "--flash-size",
                "16MB",
                "-z",
                "0x0",
                str(bootloader_path),
                "0x8000",
                str(partition_path),
                "0x10000",
                str(fw_path),
            ]

            logger.info("Flashing firmware…")
            logger.debug("Flash command: %s", " ".join(map(str, flash_cmd)))

            try:
                process = await asyncio.create_subprocess_exec(
                    *flash_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=120.0
                )
                out = stdout.decode(errors="ignore")
                err = stderr.decode(errors="ignore")
                logger.debug(out)
                if err:
                    logger.debug(err)

                if process.returncode == 0:
                    logger.info("Successfully flashed ESP32-S3")
                    for line in out.splitlines():
                        if any(
                            k in line
                            for k in (
                                "Wrote",
                                "Hash of data verified",
                                "Hard resetting",
                            )
                        ):
                            logger.info("  " + line)
                else:
                    logger.error(f"Flash failed (rc={process.returncode})")
                    logger.error(out)
                    logger.error(err)
            except asyncio.TimeoutError:
                logger.error("Flash operation timed out.")
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass
                return

        except Exception as e:
            logger.error(f"Failed to flash ESP32 on {device_port}: {e}", exc_info=True)

    async def _flash_usb_device(self, device_port):
        """Public flash method with lock acquisition for direct USB flashing"""
        async with self.flash_lock:
            await self._flash_usb_device_internal(device_port)

    async def _handle_new_usb_device(self, device_port):
        if device_port in self.devices_being_flashed:
            logger.debug(f"Device {device_port} already being flashed, skipping")
            return

        logger.info(f"New USB ESP32 device detected: {device_port}")

        self.devices_being_flashed.add(device_port)

        try:
            logger.info(f"Flashing USB device {device_port} (newly plugged in)")
            await self._flash_usb_device(device_port)
            await asyncio.sleep(5)

        finally:
            await asyncio.sleep(60)
            self.devices_being_flashed.discard(device_port)

    async def _monitor_usb_devices(self):
        """Monitor for new USB ESP32 devices and handle them intelligently"""
        logger.info("Starting USB device monitoring...")

        # Initialize with current devices - log details only on startup
        self.known_usb_devices = set(
            await self._get_usb_esp32_devices(log_devices=False)
        )
        if self.known_usb_devices:
            logger.info(
                f"Initial USB ESP32 devices connected: {self.known_usb_devices}"
            )
        else:
            logger.info("No USB ESP32 devices connected on startup")

        while True:
            try:
                # Don't log device details during monitoring - only during startup
                current_devices = await self._get_usb_esp32_devices(log_devices=False)
                current_devices_set = set(current_devices)

                # Find newly connected devices
                new_devices = current_devices_set - self.known_usb_devices

                # Find disconnected devices
                disconnected_devices = self.known_usb_devices - current_devices_set

                if disconnected_devices:
                    logger.info(f"ESP32 devices disconnected: {disconnected_devices}")

                if new_devices:
                    logger.info(f"New ESP32 devices detected: {new_devices}")
                    for device in new_devices:
                        # Use the new intelligent handler instead of auto-flashing
                        asyncio.create_task(self._handle_new_usb_device(device))

                self.known_usb_devices = current_devices_set
                await asyncio.sleep(2)  # Check every 2 seconds

            except asyncio.CancelledError:
                logger.info("USB monitoring was cancelled")
                break
            except Exception as e:
                logger.error(f"Error in USB monitoring: {e}")
                await asyncio.sleep(5)  # Wait longer on error

    async def _get_usb_esp32_devices(self, log_devices=False):
        try:
            process = await asyncio.create_subprocess_exec(
                "python3",
                "-m",
                "serial.tools.list_ports",
                "-v",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await process.communicate()

            # Only log all devices when specifically requested (like during startup)
            if log_devices:
                logger.debug("All USB devices:")
                all_lines = stdout.decode().split("\n")
                for line in all_lines:
                    if line.strip():
                        logger.debug(f"  {line}")
            else:
                all_lines = stdout.decode().split("\n")

            devices = []
            lines = all_lines
            i = 0
            while i < len(lines):
                line = lines[i].strip()
                if not line:
                    i += 1
                    continue

                # Check if this line starts with a device path (like /dev/ttyACM0)
                if line.startswith("/dev/"):
                    device_port = line.split()[0]  # Get just the device path

                    # Check the description and hwid lines that follow
                    description = ""
                    hwid = ""

                    # Look at the next few lines for desc: and hwid:
                    j = i + 1
                    while j < len(lines) and j < i + 5:  # Check up to 5 lines ahead
                        next_line = lines[j].strip()
                        if next_line.startswith("desc:"):
                            description = next_line
                        elif next_line.startswith("hwid:"):
                            hwid = next_line
                        elif next_line.startswith("/dev/"):
                            # Hit another device, stop looking
                            break
                        j += 1

                    # Check if this device matches ESP32 identifiers
                    combined_info = f"{description} {hwid}".upper()
                    esp32_identifiers = [
                        "ESP32",  # Generic ESP32
                        "10C4:EA60",  # Silicon Labs CP210x
                        "CP210",  # CP2102/CP2104 chips
                        "1A86:7523",  # CH340 chips
                        "CH340",  # CH340 series
                        "CH341",  # CH341 series
                        "303A:1001",  # Espressif USB JTAG/serial debug unit
                        "USB JTAG/serial DEBUG UNIT",  # Description match
                    ]

                    if any(
                        identifier in combined_info
                        for identifier in [id.upper() for id in esp32_identifiers]
                    ):
                        devices.append(device_port)
                        # Only log during detailed logging (startup)
                        if log_devices:
                            logger.debug(f"Detected ESP32 device: {device_port}")
                            logger.debug(f"  {description}")
                            logger.debug(f"  {hwid}")

                i += 1

            if log_devices:
                logger.debug(f"Detected USB ESP32 devices: {devices}")
            return devices

        except Exception as e:
            logger.error(f"Error detecting USB ESP32 devices: {e}")
            logger.error(
                f"stderr: {stderr.decode() if 'stderr' in locals() else 'N/A'}"
            )
            return []

    def _get_expected_firmware_version(self):
        """Get the expected firmware version from CMake-generated build file"""
        try:
            # Read the version file created by CMake during ESP32 build
            if os.path.exists(self.version_file):
                with open(self.version_file, "r") as f:
                    version_data = json.load(f)
                    version = version_data.get("version")
                    logger.debug(f"Newest firmware version: {version}")
                    return version
            else:
                logger.warning(f"Version file not found at {self.version_file}")
                logger.warning("Make sure to build the ESP32 firmware first")
                return None

        except Exception as e:
            logger.error(f"Error reading firmware version: {e}")
            return None

    async def check_for_ota_updates(self):
        """Check all connected ESP32 devices for firmware updates and trigger OTA if needed"""
        expected_version = self._get_expected_firmware_version()
        if not expected_version:
            logger.warning(
                "Cannot check for OTA updates - expected firmware version unknown"
            )
            return

        ota_candidates = []

        if len(self.esp32_devices.items()) == 0:
            logger.info(f"No ESP32 devices for OTA updates.")
            return

        for mac, device_info in self.esp32_devices.items():
            if not self._is_device_online(mac):
                continue

            current_version = device_info.get("firmware_version", "unknown")
            if current_version != expected_version:
                logger.info(
                    f"ESP32 {mac} needs OTA update: {current_version} -> {expected_version}"
                )
                ota_candidates.append((mac, device_info))

        if not ota_candidates:
            logger.info("All ESP32 devices are up to date")
            return

        logger.info(f"Found {len(ota_candidates)} devices needing OTA updates")

        for mac, device_info in ota_candidates:
            device_ip = device_info.get("ip_address")
            if device_ip:
                success = await self._trigger_ota_update(device_ip, mac)
                if success:
                    logger.info(f"OTA update triggered for {mac}")
                else:
                    logger.error(f"Failed to trigger OTA update for {mac}")
                # Add delay between updates to avoid overwhelming network
                await asyncio.sleep(2)

    async def handle_force_usb_flash(self, request):
        """Force flash a specific USB device regardless of version"""
        try:
            data = await request.json()
            device_port = data.get("device_port")

            if not device_port:
                return web.json_response(
                    {"status": "error", "message": "device_port required"}, status=400
                )

            # Check if device exists
            current_devices = await self._get_usb_esp32_devices()
            if device_port not in current_devices:
                return web.json_response(
                    {"status": "error", "message": f"Device {device_port} not found"},
                    status=404,
                )

            logger.info(f"Force flashing USB device: {device_port}")
            await self._flash_usb_device(device_port)

            return web.json_response(
                {"status": "success", "message": f"Flashing {device_port}"}
            )

        except Exception as e:
            logger.error(f"Error in force USB flash: {e}")
            return web.json_response({"status": "error", "message": str(e)}, status=500)

    async def handle_trigger_ota_updates(self, request):
        """API endpoint to trigger OTA updates check"""
        try:
            logger.info("OTA updates check triggered via API")
            await self.check_for_ota_updates()
            return web.json_response(
                {"status": "success", "message": "OTA update check completed"}
            )
        except Exception as e:
            logger.error(f"Error triggering OTA updates: {e}")
            return web.json_response({"status": "error", "message": str(e)}, status=500)
