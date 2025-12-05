#!/usr/bin/env python3

import asyncio
import gc
import signal
import sys
import time
from bluetooth.bluetooth_service import BluetoothService


class GracefulKiller:
    def __init__(self):
        self.kill_now = False
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    def _handle_signal(self, signum, frame):
        print(f"Received signal {signum}, requesting graceful shutdown...")
        self.kill_now = True


async def main():
    killer = GracefulKiller()

    bluetooth_service = BluetoothService()

    async def run_with_shutdown_check():
        try:
            await bluetooth_service.run()
        except asyncio.CancelledError:
            await bluetooth_service.cleanup()
            raise

    async def shutdown_monitor():
        while not killer.kill_now:
            await asyncio.sleep(0.1)

        print("Shutdown requested, cleaning up...")
        return "shutdown"

    try:
        tasks = []

        tasks.append(
            asyncio.create_task(
                run_with_shutdown_check()
            )
        )
        tasks.append(asyncio.create_task(shutdown_monitor()))

        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

        for task in pending:
            print(f"Cancelling task: {task}")
            task.cancel()

        await asyncio.gather(*pending, return_exceptions=True)

    except KeyboardInterrupt:
        print("KeyboardInterrupt received during cleanup")
    except Exception as e:
        print(f"Error during main execution: {e}")
    finally:
        print("Performing final cleanup...")
        try:
            await bluetooth_service.cleanup()
            gc.collect()
            time.sleep(1)
            print("Cleanup completed")
        except Exception as e:
            print(f"Error during final cleanup: {e}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Program interrupted")
    except SystemExit:
        print("System exit requested")
    sys.exit(0)
