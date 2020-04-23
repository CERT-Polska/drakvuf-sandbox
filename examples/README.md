# Examples

## Example consumer script

In `consumer.py`, we provide an exemplary script which is able to collect the results of analyses completed by DRAKVUF Sandbox.

### Installation

1. Execute:
   ```
   pip3 install -r requirements.txt
   ```
2. Create a new `config.ini` file in this directory. Copy `[minio]` and `[redis]` sections from `/etc/drakrun/config.py`.
3. Run `python3 consumer.py`
4. Done! The script will capture each completed analysis and print some logs from these analyses as an example.

