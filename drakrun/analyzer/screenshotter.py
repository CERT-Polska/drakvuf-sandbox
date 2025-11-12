import asyncio
import json
import logging
import threading
import time
from pathlib import Path

import asyncvnc
from perception import hashers
from PIL import Image

logger = logging.getLogger(__name__)


class Screenshotter:
    def __init__(
        self,
        output_dir: Path,
        vnc_host: str,
        vnc_port: int,
        vnc_password: str,
        loop_interval=5,
        max_screenshots=30,
        diff_threshold=0.05,
    ):
        self._aioloop = None
        self._thread = None
        self._task = None

        self.output_dir = output_dir
        self.vnc_host = vnc_host
        self.vnc_port = vnc_port
        self.vnc_password = vnc_password
        self.loop_interval = loop_interval
        self.max_screenshots = max_screenshots
        self.diff_threshold = diff_threshold

    async def perform(self):
        hasher = hashers.PHash()
        prev_image_hash = None
        screenshot_no = 0
        screenshot_log_path = self.output_dir / "screenshots.json"
        screenshot_dir = self.output_dir / "screenshots"
        screenshot_dir.mkdir()
        try:
            with screenshot_log_path.open("w") as screenshot_log:
                async with asyncvnc.connect(
                    host=self.vnc_host, port=self.vnc_port, password=self.vnc_password
                ) as client:
                    logger.info(f"Connected to VNC {self.vnc_host}:{self.vnc_port}")
                    while screenshot_no < self.max_screenshots:
                        pixels = await asyncio.wait_for(client.screenshot(), timeout=30)
                        timestamp = time.time()
                        image = Image.fromarray(pixels)
                        image_hash = hasher.compute(image)
                        if (
                            not prev_image_hash
                            or hasher.compute_distance(image_hash, prev_image_hash)
                            > self.diff_threshold
                        ):
                            prev_image_hash = image_hash
                            screenshot_no += 1
                            screenshot_name = (
                                screenshot_dir / f"screenshot_{screenshot_no}.png"
                            )
                            image.save(screenshot_name)
                            screenshot_log.write(
                                json.dumps(
                                    {
                                        "timestamp": timestamp,
                                        "image_hash": image_hash,
                                        "index": screenshot_no,
                                    }
                                )
                                + "\n"
                            )
                            logger.info(f"Got screenshot {screenshot_no}: {image_hash}")
                        await asyncio.sleep(self.loop_interval)
        except asyncio.CancelledError:
            logger.info("Screenshot task was cancelled.")
            # This exception is raised when stop() cancels the task.
        except Exception as e:
            logger.exception(f"Error in screenshotter task: {e}")
        finally:
            logger.info("Screenshot task finished.")

    def perform_loop(self):
        asyncio.set_event_loop(self._aioloop)
        try:
            self._task = self._aioloop.create_task(self.perform())
            self._aioloop.run_until_complete(self._task)
        finally:
            if not self._aioloop.is_closed():
                self._aioloop.close()
            logger.info("Screenshotter event loop closed.")

    def start(self):
        self._aioloop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self.perform_loop)
        self._thread.start()

    def stop(self):
        if not self._thread:
            return

        if self._aioloop and not self._aioloop.is_closed() and self._task:
            logger.info("Stopping screenshotter...")
            self._aioloop.call_soon_threadsafe(self._task.cancel)

        self._thread.join(timeout=15)

        if self._thread.is_alive():
            logger.error("Screenshotter thread did not stop in time!")

        logger.info("Screenshotter stopped.")

