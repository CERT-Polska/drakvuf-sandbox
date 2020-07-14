import os
import argparse

from karton2 import Producer, Config, Resource, Task
from drakrun.config import ETC_DIR


def main():
    parser = argparse.ArgumentParser(description='Push sample to the karton')
    parser.add_argument('sample', help='Path to the sample')
    args = parser.parse_args()

    conf = Config(os.path.join(ETC_DIR, 'config.ini'))
    producer = Producer(conf)

    with open(args.sample, "rb") as f:
        sample = Resource("sample", f.read())

    task = Task({"type": "sample", "stage": "recognized", "platform": "win32"})
    task.add_resource("sample", sample)

    producer.send_task(task)


if __name__ == "__main__":
    main()
