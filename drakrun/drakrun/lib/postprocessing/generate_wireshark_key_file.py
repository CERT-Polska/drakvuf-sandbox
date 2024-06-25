import json
import logging
import pathlib

logger = logging.getLogger(__name__)


def gen_key_file_from_log(tlsmon_log):
    key_file_content = ""
    for line in tlsmon_log:
        try:
            entry = json.loads(line)
            client_random = entry["client_random"]
            master_key = entry["master_key"]
            key_file_content += f"CLIENT_RANDOM {client_random} {master_key}\n"
        except KeyError:
            logger.exception(f"JSON is missing a required field\n{line}")
            continue
        except json.JSONDecodeError as e:
            logger.warning(f"line cannot be parsed as JSON\n{e}")
            continue
    return key_file_content


def generate_wireshark_key_file(analysis_dir: pathlib.Path) -> None:
    tlsmon_log_path = analysis_dir / "tlsmon.log"
    target_path = analysis_dir / "wireshark_key_file.txt"
    with open(tlsmon_log_path, "r") as tlsmon_log:
        key_file_content = gen_key_file_from_log(tlsmon_log)
        target_path.write_text(key_file_content)
