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
        with screenshot_log_path.open("w") as screenshot_log:
            async with asyncvnc.connect(
                host=self.vnc_host, port=self.vnc_port, password=self.vnc_password
            ) as client:
                logger.info(f"Connected to VNC {self.vnc_host}:{self.vnc_port}")
                while screenshot_no < self.max_screenshots:
                    pixels = await client.screenshot()
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

    def perform_loop(self):
        try:
            self._aioloop.run_until_complete(self.perform())
        finally:
            self._aioloop.close()

    def start(self):
        self._aioloop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self.perform_loop)
        self._thread.start()

    def stop(self):
        self._aioloop.stop()
        self._thread.join()
