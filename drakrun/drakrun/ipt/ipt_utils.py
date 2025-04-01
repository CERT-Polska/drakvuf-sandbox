import json
import logging


class CustomFormatter(logging.Formatter):
    """Logging Formatter to add colors and count warning / errors"""

    grey = "\x1b[38;21m"
    yellow = "\x1b[33;21m"
    red = "\x1b[31;21m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(levelname)8s - %(message)s"
    # format = "%(asctime)s %(levelname)8s - %(message)s (%(filename)s:%(lineno)d)"

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(CustomFormatter())

log = logging.getLogger("hax")
log.setLevel(logging.DEBUG)
log.addHandler(ch)


def load_drakvuf_output(path):
    log.info("Parsing %s...", path.name)
    result = []
    with path.open() as f:
        for line in f:
            try:
                result.append(json.loads(line))
            except json.JSONDecodeError:
                log.warning("Failed to parse %s", line)
    log.info("Loaded %d entries", len(result))
    return result


def hexint(v):
    return int(v, 16)


def get_fault_va(fault):
    return hexint(fault["VA"])


def get_fault_pa(fault):
    return hexint(fault["PA"])


def get_trap_pa(execframe):
    return hexint(execframe["TrapPA"])


def get_frame_va(execframe):
    return hexint(execframe["PageVA"])


def page_align(addr):
    return addr & ~0xFFF


def is_page_aligned(addr):
    return (addr & 0xFFF) == 0


def select_cr3(pred, entries):
    return filter(lambda v: pred(hexint(v["CR3"])), entries)
