import os
import argparse

from karton2 import Producer, Config, Resource, Task
from drakrun.config import ETC_DIR


def main():
    parser = argparse.ArgumentParser(description='Push sample to the karton')
    parser.add_argument('sample', help='Path to the sample')
    parser.add_argument('--start_command', help='e.g. start %f, %f will be replaced by file name', required=False)
    args = parser.parse_args()

    conf = Config(os.path.join(ETC_DIR, 'config.ini'))
    producer = Producer(conf)

    task = Task({"type": "sample", "stage": "recognized", "platform": "win32"})

    with open(args.sample, "rb") as f:
        sample = Resource("sample", f.read())
    task.add_resource("sample", sample)

    # Add filename
    filename = os.path.basename(args.sample)
    task.add_payload("file_name", os.path.splitext(filename)[0])

    # Extract and add extension
    extension = os.path.splitext(filename)[1][1:]
    if extension:
        task.headers['extension'] = extension

    if args.start_command is not None:
        task.add_payload("start_command", args.start_command)

    producer.send_task(task)


if __name__ == "__main__":
    main()
