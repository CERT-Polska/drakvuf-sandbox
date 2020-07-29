import json
import re
import logging
from typing import List, Dict, Iterable, Generator, Union
from datetime import datetime
from sys import argv, exit

# set this to False for more debugging
void_unknown = True


class Base:
    def __init__(self, obj: Dict, operation: str, path: str, result: str = "SUCCESS", detail: str = "", valid: bool = True):
        self.timestamp = datetime.utcfromtimestamp(float(obj["TimeStamp"])).strftime("%-I:%-M:%-S.%f %p")
        self.proc_name = obj["ProcessName"].split("\\")[-1]
        self.pid = int(obj["PID"])
        self.operation = operation
        self.path = path
        self.result = result
        self.detail = detail
        self.tid = int(obj["TID"]) if "TID" in obj else int(self.pid + 80000)
        self.valid = valid

    def __str__(self):
        # hack to avoid printing empty stuff
        if not self.valid:
            return ""

        # "Time of Day","Process Name","PID","Operation","Path","Result","Detail","TID"
        return f'"{self.timestamp}","{self.proc_name}","{self.pid}","{self.operation}","{self.path}","{self.result}","{self.detail}","{self.tid}"'


class Regmon(Base):
    def __init__(self, obj: Dict):
        # override some names that don't
        switcher = {
            "NtDeleteKey": "RegDeleteKey",
            "NtSetValueKey": "RegSetValue",
            "NtDeleteValueKey": "RegDeleteValue",
            "NtCreateKey": "RegCreateKey",
            "NtCreateKeyTransacted": "RegCreateKey",
            "NtOpenKey": "RegOpenKey",
            "NtOpenKeyEx": "RegOpenKey",
            "NtOpenKeyTransacted": "RegOpenKey",
            "NtOpenKeyTransactedEx": "RegOpenKey",
            "NtQueryKey": "RegQueryKey",
            "NtQueryMultipleValueKey": "RegQueryValue",
            "NtQueryValueKey": "RegQueryValue"
        }

        method = switcher.get(obj["Method"], "Unknown")

        if "ValueName" in obj:
            key = f"{obj['Key']}\\{obj['ValueName']}"
        else:
            key = obj["Key"]

        if "Value" in obj:
            detail = f"Type: REG_BINARY, Length: {len(obj['Value'].replace(' ', ''))}, Data: {obj['Value']}"
        else:
            detail = ""

        if obj["Method"] == "NtCreateKey":
            detail = "Desired Access: All Access, Disposition: REG_OPENED_EXISTING_KEY"

        if obj["Method"] == "NtOpenKey" or obj["Method"] == "NtOpenKeyEx":
            detail = "Desired Access: All Access"

        super().__init__(obj, method, key, detail=detail)


class Procmon(Base):
    def __init__(self, obj: Dict):
        if obj["Method"] == "NtCreateUserProcess":
            super().__init__(obj, "Process Create", obj["ImagePathName"], detail=f'PID: {obj["NewPid"]}, Command line: {obj["CmdLine"]}')

        # fallback
        if not hasattr(self, "valid") or not self.valid:
            self.valid = False


class FileTracer(Base):
    def __init__(self, obj: Dict):
        if obj["Method"] == "NtCreateFile":
            super().__init__(obj, "CreateFile", obj["FileName"], detail="OpenResult: Created, Non-Directory File")

        if obj["Method"] == "NtSetInformationFile":
            if "SrcFileName" in obj and "DstFileName" in obj:
                super().__init__(obj, "SetRenameInformationFile", obj["SrcFileName"], detail='FileName: {}'.format(obj["DstFileName"]))

        if obj["Method"] == "NtWriteFile":
            super().__init__(obj, "WriteFile", obj["FileName"])

        if obj["Method"] == "NtReadFile":
            super().__init__(obj, "ReadFile", obj["FileName"])

        # fallback
        if not hasattr(self, "valid") or not self.valid:
            self.valid = False


class Syscall(Base):
    def __init__(self, obj: Dict):
        if obj["Method"] == "NtResumeThread":
            super().__init__(obj, "Process Start", "")

        if obj["Method"] == "NtTerminateProcess":
            super().__init__(obj, "Process Exit", "")

        if obj["Method"] == "NtCreateThreadEx":
            super().__init__(obj, "Thread Create", "")

        if obj["Method"] == "NtTerminateThread":
            super().__init__(obj, "Thread Exit", "")

        # fallback
        if not hasattr(self, "valid") or not self.valid:
            self.valid = False


class Filedelete(Base):
    def __init__(self, obj: Dict):
        if obj["Method"] == "NtClose":
            super().__init__(obj, "SetDispositionInformationFile", obj["FileName"], detail="Delete: True")

        # fallback
        if not hasattr(self, "valid") or not self.valid:
            self.valid = False


"""
--- todo:
"WriteFile"); Or lst_ProcmonRow()\\Operation = "ReadFile")
"RegGetValue" And FindMapElement(map_RegistryKey(), LCase(lst_ProcmonRow()\\FullPath)))
"RegSetValue"); Or lst_ProcmonRow()\\Operation = "RegQueryValue")
"""


def parse_logs(lines: Iterable[Union[bytes, str]]) -> Generator[str, None, None]:
    # switch => get class => instantiate => str
    switcher = {
        "regmon": Regmon,
        "filetracer": FileTracer,
        "syscall": Syscall,
        "filedelete": Filedelete,
        "procmon": Procmon
    }

    try:
        first_line = json.loads(next(lines))
        injected_pid = first_line['InjectedPid']
    except Exception:
        logging.exception("Failed to get InjectedPid from first line")
        injected_pid = 0

    # prepend prolog
    yield '"Time of Day","Process Name","PID","Operation","Path","Result","Detail","TID"'
    yield '"","","","","MINIBIS_EXECUTES_SAMPLE_minibis.bat","SUCCESS","",""'
    yield '"","minibis-cpp.exe","*1*","Process Create","","SUCCESS","PID: *2*, Command line: ++++++++",""'
    yield '"","minibis-cpp.exe","*2*","Process Create","","SUCCESS","PID: {}, Command line: Explorer.EXE",""'.format(injected_pid)

    for line in lines:
        try:
            line_obj = json.loads(line)
        except Exception:
            logging.exception(f"BUG: Unparseable log entry!\n{line}")
            continue

        try:
            plugin = line_obj["Plugin"]
        except KeyError as e:
            logging.warning(f"line is missng plugin name!\n{e}")
            continue

        if plugin in switcher:
            plugin_obj = switcher[plugin]
            converted = str(plugin_obj(line_obj))
            if converted:
                yield converted
        elif not void_unknown:
            logging.info(f"unparsed: {line}")


if __name__ == "__main__":
    if len(argv) != 3:
        logging.error('unexpected number of arguments!')
        exit(1)

    with open(argv[1], "rb") as in_f:
        with open(argv[2], "w") as out_f:
            for csv_line in parse_logs(in_f):
                out_f.write(csv_line.strip() + "\n")
