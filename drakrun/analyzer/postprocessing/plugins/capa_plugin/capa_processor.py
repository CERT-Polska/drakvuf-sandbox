import functools
import itertools
import logging
import multiprocessing
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Dict, Iterator, List, Optional, TextIO, Tuple, Union

import capa.features.address as ca
import orjson
from capa.capabilities.common import find_capabilities
from capa.engine import MatchResults as EngineMatchResults
from capa.features.common import Result
from capa.features.extractors.base_extractor import ProcessFilter
from capa.features.extractors.drakvuf.extractor import DrakvufExtractor
from capa.helpers import get_auto_format
from capa.loader import get_extractor
from capa.main import (
    BACKEND_DOTNET,
    BACKEND_VIV,
    FORMAT_DOTNET,
    OS_WINDOWS,
    UnsupportedFormatError,
)
from capa.render.result_document import MatchResults as ResultDocumentMatchResults
from capa.rules import Rule, RuleSet, get_rules, get_rules_and_dependencies

from drakrun.lib.config import load_config
from drakrun.lib.paths import DUMPS_DIR, DUMPS_ZIP

logger = logging.getLogger(__name__)


def check_rules_directory_exist(path: Path) -> bool:
    # this method checks whether a non-empty directory exists
    return path.is_dir() and any(path.iterdir())


def find_process_in_pstree(pstree: List, pid: int) -> Dict:
    """This methods searches for a process in the generated process_tree.json file"""
    for process in pstree:
        if process["pid"] == pid:
            return process

        child_processes = find_process_in_pstree(process["children"], pid)
        if child_processes:
            return child_processes

    # return None in case the process is not found
    raise RuntimeError(f"PID {pid} not found in the process tree")


def get_all_child_processes(process: Dict) -> Iterator[int]:
    """This method returns all of the child processes pids (recursively), including their parent's"""
    for p in process["children"]:
        yield from get_all_child_processes(p)

    # yield current node's pid
    yield process["pid"]


def filter_rules(rules: RuleSet, filter_function=None) -> RuleSet:
    """this method filters the given rules folder following arbitrary logic (specified by filter_function)"""
    rules = list(rules.rules.values())
    reduced_rules = list(filter(filter_function, rules))

    # filter the given rules folder using the specified boolean function
    filtered_rules = set()
    for rule in reduced_rules:
        filtered_rules.update(get_rules_and_dependencies(rules, rule.name))

    # generate the new ruleset, and return it
    return RuleSet(list(filtered_rules))


def get_malware_processes(inject_path: Path, pstree_path: Path) -> List[int]:
    # this method gets all the pids in the Drakvuf report that are associated with malware
    with inject_path.open("r") as f:
        # we use the injected processes log to get the malware process' parent pid
        injected_processes = [orjson.loads(line) for line in f]

    with pstree_path.open("r") as f:
        # we use the process tree to get all of the malware process' child processes
        pstree = orjson.loads(f.read())

    # make sure that inject.log has only one entry
    if len(injected_processes):
        raise ValueError("inject.log has more than one entry")

    malware_injection_log = injected_processes[0]

    # get the parent malware process' pid and process name
    malware_pid: int = malware_injection_log["InjectedPid"]

    # find the malware process' sub-tree in the overall process tree
    malware_process: Dict = find_process_in_pstree(pstree, malware_pid)

    # return a list of all spawned malware processes (does not include process injection)
    return list(get_all_child_processes(malware_process))


def get_drakvuf_feature_extractor(
    calls: Iterator[Dict],
) -> DrakvufExtractor:
    """Wrapper routing for initializing the Drakvuf feature extractor"""
    return DrakvufExtractor.from_report(calls)


def decode_json_lines(fd: TextIO) -> Iterator[Dict]:
    # read and decode json lines into a list of dictionaries
    for line in fd:
        try:
            # we use orjson for a small performance improvement
            yield orjson.loads(line.strip())
        except orjson.JSONDecodeError:
            # sometimes Drakvuf reports bad method names and/or malformed JSON
            logger.debug("bad drakvuf log line: %s", line)


def dynamic_capa_analysis(
    analysis_dir: Path,
    rules: RuleSet,
    malware_pids: Optional[List[int]] = None,
) -> Tuple[Path, ResultDocumentMatchResults]:

    # save all api calls and native calls into one list which gets sorted by capa later on.
    calls = []

    # read api calls
    if (analysis_dir / "apimon.log").exists():
        with (analysis_dir / "apimon.log").open("r", errors="ignore") as apimon_fd:
            calls += list(decode_json_lines(apimon_fd))
    else:
        logger.debug("missing apimon.log file")

    # read syscalls
    if (analysis_dir / "syscall.log").exists():
        with (analysis_dir / "syscall.log").open("r", errors="ignore") as syscall_fd:
            calls += list(decode_json_lines(syscall_fd))
    else:
        logger.debug("missing syscall.log file")

    if not calls:
        raise RuntimeError(
            "both syscall.log and apimon.log are either empty or non-existent"
        )

    # initialize the Drakvuf capa feature extractor with the captured calls
    extractor = get_drakvuf_feature_extractor(calls)

    # apply a filter to the extractor if we wish to only analyze a specific set of processes
    if malware_pids:
        extractor = ProcessFilter(extractor, malware_pids)

    # extract dymamic capabilities
    capabilities, _ = find_capabilities(rules, extractor)

    # analysis_dir is returned for conformity reasons with the ttp generation function (same routine for both static and dynamic capability extraction)
    return analysis_dir, capabilities


def get_process_memory_dumps(analysis_dir: Path, pid: int) -> Iterator[str]:
    """get the memory dumps from a specific process."""
    # this is used mainly to get the memdumps by a malware process
    with (analysis_dir / "memdump.log").open("r") as f:
        for line in f:
            dump = orjson.loads(line)
            if dump["PID"] == pid:
                yield dump["DumpFilename"]


def static_capa_analysis(
    dump_path: Path, rules: RuleSet
) -> Tuple[Path, ResultDocumentMatchResults]:
    """get the input file's capa format"""
    try:
        input_format = get_auto_format(dump_path)
    except UnsupportedFormatError:
        logger.debug("dump %s has an unsupported format", dump_path)
        return

    # get the input file's adequate analysis backend
    if input_format == FORMAT_DOTNET:
        backend = BACKEND_DOTNET
    else:
        backend = BACKEND_VIV

    # get the right capa feature extractor for the input: Vivisect, .NET, etc.
    extractor = get_extractor(
        dump_path,
        input_format,
        OS_WINDOWS,
        backend=backend,
        sigpaths=[],
        should_save_workspace=False,
        disable_progress=False,
        sample_path=dump_path,
    )

    # extract capabilities from the file, and ignore the returned metadata
    capabilities, _ = find_capabilities(rules, extractor, disable_progress=True)

    # return the capabilities alongside the memdump's path (for TTP categorization purposes)
    return dump_path, capabilities


def static_memory_dumps_capa_analysis(
    analysis_dir: Path,
    rules: RuleSet,
    worker_pool_processes: int,
    malware_pids: List[int],
) -> Iterator[Tuple[Path, ResultDocumentMatchResults]]:
    malware_dumps = list(
        itertools.chain(
            *(get_process_memory_dumps(analysis_dir, pid) for pid in malware_pids)
        )
    )

    with TemporaryDirectory() as dump_extraction_directory:
        # extract all memory dumps temporarily into a dumps/ folder
        with zipfile.ZipFile(analysis_dir / DUMPS_ZIP, "r") as zip_ref:
            # extract the memory dumps into the temporary directory
            zip_ref.extractall(dump_extraction_directory)
            dumps = Path(dump_extraction_directory) / DUMPS_DIR

        # extract the capabilities within each memory dump, one per thread
        pool = multiprocessing.Pool(processes=worker_pool_processes)
        yield from pool.starmap(
            static_capa_analysis, map(lambda dump: (dumps / dump, rules), malware_dumps)
        )


def format_capa_address(address: Union[Tuple, ca.Address]) -> Dict:
    """This method formats capa address (in the format of tuples) into a single dictionary"""
    if isinstance(address, tuple):
        return functools.reduce(
            lambda a, b: a | b, [format_capa_address(addr) for addr in address]
        )
    elif isinstance(
        address,
        (ca.AbsoluteVirtualAddress, ca.RelativeVirtualAddress, ca.FileOffsetAddress),
    ):
        return {"address": hex(address)}
    elif isinstance(address, ca.DNTokenAddress):
        return {"token": hex(address)}
    elif isinstance(address, ca.DNTokenOffsetAddress):
        return {
            **format_capa_address(ca.DNTokenAddress(address.token)),
            "offset": address.offset,
        }
    elif isinstance(address, ca.ProcessAddress):
        return {"ppid": address.ppid, "pid": address.pid}
    elif isinstance(address, ca.ThreadAddress):
        # for the time being, we only collect the PID and PPID of a TTP
        return {**format_capa_address(address.process)}
    elif isinstance(address, ca.DynamicCallAddress):
        # for the time being, we only collect the PID and PPID of a TTP
        return {**format_capa_address(address.thread)}
    elif isinstance(address, ca._NoAddress):
        # empty address
        return {}
    else:
        logger.debug("Encountered unknown address type: %s", type(address))
        return {"address": address}


def construct_ttp_block(
    rule: Rule, addresses: List[Tuple[ca.Address, Result]]
) -> Dict[str, Any]:
    name = rule.name.split("/")[0]
    mbc = rule.meta.get("mbc", None)
    attck = rule.meta.get("att&ck", None)
    occurrences = [format_capa_address(address=address) for address, _ in addresses]
    occurrences = [
        dict(t) for t in {tuple(d.items()) for d in occurrences}
    ]  # remove duplicate addresses

    ttp_block = dict()
    ttp_block.update({"name": name})
    ttp_block.update({"mbc": mbc} if mbc else {})
    ttp_block.update({"att&ck": attck} if attck else {})
    ttp_block.update({"occurrences": occurrences})
    return ttp_block


def construct_ttp_blocks(
    rules: RuleSet,
    capabilities_per_file: List[Tuple[Path, EngineMatchResults]],
    filter_function=None,
) -> Iterator[Dict[str, Any]]:
    """construct a ttp block for each extracted capability"""
    for _, capabilities in capabilities_per_file:
        for name, addresses in capabilities.items():
            if not filter_function or filter_function(rules[name]):
                yield construct_ttp_block(rules[name], addresses)


def capa_analysis(analysis_dir: Path) -> None:
    config = load_config().capa

    # capa rules directory
    capa_rules_dir = config.rules_directory

    """check and prepare the rules folder"""
    if not check_rules_directory_exist(capa_rules_dir):
        # in case of a missing/empty rules folder, clone the official capa rules
        raise RuntimeError("capa rules directory is empty or non-existant")

    # get rules and filter them
    rules = get_rules([capa_rules_dir])
    rules = filter_rules(
        rules, filter_function=lambda rule: rule.meta.get("att&ck", None)
    )  # select only rules with an att&ck entry specified

    # get malware-related pids if requested by configuration
    malware_pids = None
    if config.analyze_only_malware_pids:
        malware_pids = get_malware_processes(
            inject_path=analysis_dir / "inject.log",
            pstree_path=analysis_dir / "process_tree.json",
        )

    # extract capabilities from the Drakvuf report
    if config.analyze_drakmon_log:
        dynamic_capabilities = dynamic_capa_analysis(
            analysis_dir, rules, malware_pids=malware_pids
        )

        # write the extracted TTPs to the analysis dir
        with (analysis_dir / "ttps.json").open("wb") as f:
            for ttp in construct_ttp_blocks(
                rules,
                [dynamic_capabilities],
                filter_function=lambda rule: rule.meta.get("att&ck", None),
            ):
                f.write(orjson.dumps(ttp))
                f.write(b"\n")

    # extract capabilities from the memory dumps
    if config.analyze_memdumps:
        static_capabilities_per_file = static_memory_dumps_capa_analysis(
            analysis_dir, rules, config.worker_pool_processes, malware_pids=malware_pids
        )

        # create a folder containing the TTPs corresponding to each dump
        dumps_ttp_path = analysis_dir / "dumps_ttp"
        dumps_ttp_path.mkdir(parents=True, exist_ok=True)

        # dump the TTPs for each memdump into a jsonl file
        for dump_name, static_capabilities in static_capabilities_per_file:
            with (dumps_ttp_path / dump_name).open("wb") as f:
                for ttp in construct_ttp_blocks(
                    rules, [(dump_name, static_capabilities)]
                ):
                    f.write(orjson.dumps(ttp))
                    f.write(b"\n")


if __name__ == "__main__":
    import sys

    capa_analysis(Path(sys.argv[1]))
