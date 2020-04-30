# Examples

## Initial installation
```
pip3 install -r requirements.txt
```

## Example producer script

In `push_sample.py`, we provide an example of a script which uploads a new sample into DRAKVUF Sandbox and optionally waits until it is fully processed.

### Usage

Run `python3 push_sample.py sample.exe`.

## Example consumer script

In `consumer.py`, we provide an exemplary script which is able to collect the results of analyses completed by DRAKVUF Sandbox.

### Usage

1. Create a new `config.ini` file in this directory. Copy `[minio]` and `[redis]` sections from `/etc/drakrun/config.py`.
2. Run `python3 consumer.py`
3. Done! The script will capture each completed analysis and print some logs from these analyses as an example.

