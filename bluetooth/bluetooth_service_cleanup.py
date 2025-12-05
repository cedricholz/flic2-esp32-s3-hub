import asyncio
import concurrent.futures

from log.log import logger as base_logger

logger = base_logger.getChild("BT")


class BlueToothServiceCleanup:

    async def cleanup(self):
        logger.info("Starting Bluetooth service cleanup...")

        if hasattr(self, "usb_monitor_task") and self.usb_monitor_task:
            self.usb_monitor_task.cancel()
            try:
                await self.usb_monitor_task
            except asyncio.CancelledError:
                pass
            self.usb_monitor_task = None

        if hasattr(self, "ota_check_task") and self.ota_check_task:
            self.ota_check_task.cancel()
            try:
                await self.ota_check_task
            except asyncio.CancelledError:
                pass
            self.ota_check_task = None

        if hasattr(self, "zeroconf") and self.zeroconf and hasattr(self, "service_info") and self.service_info:
            try:
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    await asyncio.wait_for(
                        asyncio.get_event_loop().run_in_executor(executor, self._cleanup_mdns_sync),
                        timeout=3.0,
                    )
            except (asyncio.TimeoutError, Exception) as e:
                logger.warning(f"mDNS cleanup error: {e}")
            self.service_info = None
            self.zeroconf = None

        if hasattr(self, "site") and self.site:
            try:
                await asyncio.wait_for(self.site.stop(), timeout=5.0)
            except (asyncio.TimeoutError, Exception) as e:
                logger.warning(f"TCP site stop error: {e}")
            self.site = None

        if hasattr(self, "runner") and self.runner:
            try:
                await asyncio.wait_for(self.runner.cleanup(), timeout=5.0)
            except (asyncio.TimeoutError, Exception) as e:
                logger.warning(f"App runner cleanup error: {e}")
            self.runner = None

        self.app = None
        logger.info("Cleanup completed")

    def _cleanup_mdns_sync(self):
        try:
            if self.zeroconf and self.service_info:
                self.zeroconf.unregister_service(self.service_info)
                self.zeroconf.close()
        except Exception as e:
            logger.warning(f"mDNS cleanup error: {e}")