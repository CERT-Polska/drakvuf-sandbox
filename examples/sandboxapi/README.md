# Python client for [DRAKVUF Sandbox](https://github.com/CERT-Polska/drakvuf-sandbox)

## Overview

sandboxapi is a client implementation in Python for the API exposed by
[DRAKVUF Sandbox](https://github.com/CERT-Polska/drakvuf-sandbox). Below, you'll find some installation and usage
instructions.

# Prerequisites:
- Python 3
- A running DRAKVUF Sandbox instance on an accessible host

## Installation

* Clone this repo
* Run:

    ```bash
    pip install .
    ```

## Using the API Programmatically

### Instantiating a client

```python
# specify your URL
client = Client(url="http://localhost:6300")
# or specify none and use the default of http://localhost:6300
client = Client()
```

### Submit a file

```python
# submit a file and get the UUID of the new job in response
uuid = client.post_file("/path/to/file")
```

### Check job status

```python
# get the status of the given job (e.g. "pending")
status = client.get_status("<UUID>")
```

### Retrieve mem dump

```python
# download the mem dump for a job, with the HTTP code and filepath written to returned
status_code, outfilepath = client.get_dump("<UUID>")
```

### Retrieve log

```python
# download the log for a job, with the HTTP code and filepath written to returned
status_code, outfilepath = client.get_log("<UUID>", "apimon")
```

Options for logs to pull include (non-exhaustive):
* apimon
* cpuidmon
* delaymon
* dkommon
* exmon
* filetracer
* memdump
* procmon
* regmon
* syscalls

## Using the API from the CLI

```
$ sandboxcli -h
usage: sandboxcli [-h] [-f FILEPATH] [-d DUMP_UUID] [-l LOG] [-s STATUS_UUID]
                  [-u URL] [-w]

Interact with DRAKVUF Sandbox

optional arguments:
  -h, --help            show this help message and exit
  -f FILEPATH, --filepath FILEPATH
                        Path for file to be submitted
  -d DUMP_UUID, --dump-uuid DUMP_UUID
                        UUID of the memory dump to download
  -l LOG, --log-download LOG
                        The UUID and the name of the log to download,
                        specified as <UUID>:<logname>
  -s STATUS_UUID, --status-uuid STATUS_UUID
                        UUID of the job to check the status of
  -u URL, --url URL     DRAKVUF Sandbox server URL (default:
                        http://localhost:6300)
  -w, --wait            If passed, CLI won't return until analysis ends
```

### Submit a file

You can submit a file asynchronously

```bash
$ sandboxcli -f sample.exe
Submitted file sample.exe with job UUID <UUID>
```

Or, you can wait until the job completes
```bash
$ sandboxcli -f sample.exe
Submitted file sample.exe with job UUID <UUID>
Task <UUID> pending... (0s)
Task <UUID> pending... (10s)
Task <UUID> pending... (20s)
Task <UUID> pending... (30s)
Task <UUID> pending... (40s)
Task <UUID> pending... (50s)
Task <UUID> pending... (60s)
Task <UUID> pending... (70s)
Task <UUID> pending... (80s)
Task <UUID> pending... (90s)
...
```

### Check job status

```bash
$ sandboxcli -s <UUID>
Job <UUID>: pending
```

### Retrieve mem dump

```bash
$ sandboxcli -d <UUID>
200: downloaded <UUID>.dump
```

### Retrieve log

```bash
$ sandboxcli -l <UUID>:apimon
200: downloaded <UUID>-apimon.json
```

## Future Work

* Add options for run time and detonation command to `post_file`