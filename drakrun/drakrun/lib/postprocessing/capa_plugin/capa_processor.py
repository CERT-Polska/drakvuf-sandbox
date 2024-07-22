import functools
import itertools
import logging
import multiprocessing
import shutil
import zipfile
from pathlib import Path
from typing import Any, BinaryIO, Dict, Iterator, List, Optional, Tuple, Union

import capa
import capa.capabilities
import capa.capabilities.common
import capa.engine
import capa.features
import capa.features.address
import capa.features.common
import capa.features.extractors
import capa.features.extractors.base_extractor
import capa.features.extractors.drakvuf
import capa.features.extractors.drakvuf.extractor
import capa.helpers
import capa.loader
import capa.main
import capa.render
import capa.render.json
import capa.render.result_document
import capa.rules
import orjson

# rules related configuration
capa_rules_dir = Path("./capa-rules")

# analysis configuration
analyze_malware_pids_only = False
perform_static_analysis = False
perform_dynamic_analysis = True

logger = logging.getLogger(__name__)


def check_rules_directory_exist(path: Path) -> bool:
    # this method checks whether a non-empty directory exists
    return path.is_dir() and any(path.iterdir())


def find_process_in_pstree(pstree: List, pid: int, procname: str) -> Dict:
    # this methods searches for a process in the generated process_tree.json file
    for process in pstree:
        if process["pid"] == pid:
            return process
        else:
            child_processes = find_process_in_pstree(process["children"], pid, procname)
            if child_processes:
                return child_processes

    # return None in case the process is not found
    return None


def get_all_child_processes(process: Dict) -> Iterator[int]:
    # this method returns all of the child processes pids (recursively), including their parent's
    for p in process["children"]:
        yield from get_all_child_processes(p)

    # yield current node's pid
    yield process["pid"]


def get_rules(rules_dir: List[Path]) -> Optional[capa.rules.RuleSet]:
    try:
        rules = capa.rules.get_rules(rules_dir)
    except (IOError, capa.rules.InvalidRule, capa.rules.InvalidRuleSet):
        # display the official capa error message in case there exists any malformed capa rules
        rules = None
        logger.exception(
            "Make sure your file directory contains properly formatted capa rules. You can download the standard "
            + "collection of capa rules from https://github.com/mandiant/capa-rules/releases."
        )
        logger.error(
            "Please ensure you're using the rules that correspond to your major version of capa (%s)",
            capa.version.get_major_version(),
        )
        logger.error(
            "Or, for more details, see the rule set documentation here: %s",
            "https://github.com/mandiant/capa/blob/master/doc/rules.md",
        )

    return rules


def filter_rules(
    rules: capa.rules.RuleSet, filter_function=lambda rule: rule
) -> capa.rules.RuleSet:
    # this method filters the given rules folder following arbitrary logic (specified by filter_function)
    rules = list(rules.rules.values())
    reduced_rules = list(filter(filter_function, rules))

    # filter the given rules folder using the specified boolean function
    filtered_rules = set()
    for rule in reduced_rules:
        filtered_rules.update(
            set(capa.rules.get_rules_and_dependencies(rules, rule.name))
        )

    # generate the new ruleset, and return it
    return capa.rules.RuleSet(list(filtered_rules))


def get_malware_processes(
    metadata_path: Path, inject_path: Path, pstree_path: Path
) -> Optional[List[int]]:
    # this method gets all the pids in the Drakvuf report that are associated with malware
    with metadata_path.open("r") as f:
        # we use the metadata file to get the analysis' start command
        metadata = orjson.loads(f.read())

    with inject_path.open("r") as f:
        # we use the injected processes log to get the malware process' parent pid
        injected_processes = [orjson.loads(line) for line in f]

    with pstree_path.open("r") as f:
        # we use the process tree to get all of the malware process' child processes
        pstree = orjson.loads(f.read())

    # make sure we have the right inject.log entry (using the metadata.json file)
    malware_injection_log: str = next(
        filter(
            lambda line: line["ProcessName"] == metadata["start_command"],
            injected_processes,
        )
    )

    # get the parent malware process' pid and process name
    malware_pid: int = malware_injection_log["InjectedPid"]
    malware_procname: str = malware_injection_log["ProcessName"]

    # find the malware process' sub-tree in the overall process tree
    try:
        malware_process: Dict = find_process_in_pstree(
            pstree, malware_pid, malware_procname
        )
    except ValueError:
        # malware pid not found, analyze entire log instead
        return None

    # return a list of all spawned malware processes (does not include process injection)
    return list(get_all_child_processes(malware_process))


def get_drakvuf_feature_extractor(
    calls: Iterator[Dict],
) -> capa.features.extractors.drakvuf.extractor.DrakvufExtractor:
    # wrapper routing for initializing the Drakvuf feature extractor
    return capa.features.extractors.drakvuf.extractor.DrakvufExtractor.from_report(
        calls
    )


def decode_json_lines(fd: BinaryIO) -> Iterator[Dict]:
    # read and decode json lines into a list of dictionaries
    for line in fd:
        try:
            # we use orjson for a small performance improvement
            line_s = line.strip()
            obj = orjson.loads(line_s)
            yield obj
        except (orjson.JSONDecodeError):
            # sometimes Drakvuf reports bad method names and/or malformed JSON
            logger.debug("bad drakvuf log line: %s", line)


def dynamic_capa_analysis(
    analysis_dir: Path,
    rules: capa.rules.RuleSet,
    malware_pids: Optional[List[int]] = None,
) -> Tuple[Path, capa.render.result_document.MatchResults]:

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

    # initialize the Drakvuf capa feature extractor with the captured calls
    extractor = get_drakvuf_feature_extractor(calls)

    # apply a filter to the extractor if we wish to only analyze a specific set of processes
    if malware_pids:
        extractor = capa.features.extractors.base_extractor.ProcessFilter(
            extractor, malware_pids
        )

    # extract dymamic capabilities
    capabilities, _ = capa.capabilities.common.find_capabilities(rules, extractor)

    # analysis_dir is returned for conformity reasons with the ttp generation function (same routine for both static and dynamic capability extraction)
    return analysis_dir, capabilities


def get_process_memory_dumps(analysis_dir: Path, pid: int) -> Iterator[str]:
    # get the memory dumps from a specific process.
    # this is used mainly to get the memdumps by a malware process
    with (analysis_dir / "memdump.log").open("r") as f:
        for line in f:
            dump = orjson.loads(line)
            if dump["PID"] == pid:
                yield dump["DumpFilename"]


def static_capa_analysis(
    dump_path: Path, rules: capa.rules.RuleSet
) -> Tuple[Path, capa.render.result_document.MatchResults]:

    # get the input file's capa format
    try:
        input_format = capa.helpers.get_auto_format(dump_path)
    except capa.main.UnsupportedFormatError:
        logger.debug("dump %s has an unsupported format", dump_path)
        return

    # get the input file's adequate analysis backend
    if input_format == capa.main.FORMAT_DOTNET:
        backend = capa.main.BACKEND_DOTNET
    else:
        backend = capa.main.BACKEND_VIV

    # get the right capa feature extractor for the input: Vivisect, .NET, etc.
    extractor = capa.loader.get_extractor(
        dump_path,
        input_format,
        capa.main.OS_WINDOWS,
        backend,
        [],
        False,
        False,
        dump_path,
    )

    # extract capabilities from the file, and ignore the returned metadata
    capabilities, _ = capa.capabilities.common.find_capabilities(
        rules, extractor, disable_progress=True
    )

    # return the capabilities alongside the memdump's path (for TTP categorization purposes)
    return dump_path, capabilities


def static_memory_dumps_capa_analysis(
    analysis_dir: Path, rules: capa.rules.RuleSet, malware_pids: List[int] = []
) -> Iterator[Tuple[Path, capa.render.result_document.MatchResults]]:
    malware_dumps = list(
        itertools.chain(
            *(get_process_memory_dumps(analysis_dir, pid) for pid in malware_pids)
        )
    )

    # extract all memory dumps temporarily into a dumps/ folder
    with zipfile.ZipFile(analysis_dir / "dumps.zip", "r") as zip_ref:
        try:
            # try to extract the memory dumps into the analysis folder
            zip_ref.extractall(analysis_dir)
            dumps = analysis_dir / "dumps"
        except PermissionError:
            # in case of missing permissions, extract into /tmp
            zip_ref.extractall(Path("/tmp"))
            dumps = Path("/tmp") / "dumps"

    # extract the capabilities within each memory dump, one per thread
    pool = multiprocessing.Pool(processes=len(malware_dumps))
    yield from pool.starmap(
        static_capa_analysis, map(lambda dump: (dumps / dump, rules), malware_dumps)
    )

    # try to remove the temporarily created folder
    try:
        shutil.rmtree(dumps)
    except PermissionError:
        logger.debug(
            "Permission Denied: Could not remove temporary dumps.zip extraction folder"
        )


def format_capa_address(address: Union[Tuple, capa.features.address.Address]) -> Dict:
    # this method formats capa address (in the format of tuples) into a single dictionary
    if isinstance(address, tuple):
        return functools.reduce(
            lambda a, b: a | b, [format_capa_address(addr) for addr in address]
        )
    elif isinstance(
        address,
        (
            capa.features.address.AbsoluteVirtualAddress,
            capa.features.address.RelativeVirtualAddress,
            capa.features.address.FileOffsetAddress,
        ),
    ):
        return {"address": hex(address)}
    elif isinstance(address, capa.features.address.DNTokenAddress):
        return {"token": address.token}
    elif isinstance(address, capa.features.address.DNTokenOffsetAddress):
        return {**format_capa_address(address.token), "offset": address.offset}
    elif isinstance(address, capa.features.address.ProcessAddress):
        return {"ppid": address.ppid, "pid": address.pid}
    elif isinstance(address, capa.features.address.ThreadAddress):
        # for the time being, we only collect the PID and PPID of a TTP
        return {**format_capa_address(address.process)}
    elif isinstance(address, capa.features.address.DynamicCallAddress):
        # for the time being, we only collect the PID and PPID of a TTP
        return {**format_capa_address(address.thread)}
    elif isinstance(address, capa.features.address._NoAddress):
        # empty address
        return {}
    else:
        logger.debug("Encountered unknown address type: %s", type(address))
        return {"address": address}


def construct_ttp_block(
    rule: capa.rules.Rule, addresses: capa.features.address
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
    rules: capa.rules.RuleSet,
    capabilities_per_file: List[Tuple[Path, capa.engine.MatchResults, Any]],
    filter_function=lambda rule: rule,
) -> Iterator[Dict[str, Any]]:

    # construct a ttp block for each extracted capability
    for _, capabilities in capabilities_per_file:
        for name, addresses in capabilities.items():
            if filter_function(rules[name]):
                yield construct_ttp_block(rules[name], addresses)


def capa_analysis(analysis_dir: Path) -> None:
    # check and prepare the rules folder
    if not check_rules_directory_exist(capa_rules_dir):
        # in case of a missing/empty rules folder, clone the official capa rules
        logger.exception("capa rules directory is empty or non-existant")

    # get rules and filter them
    rules = get_rules([capa_rules_dir])
    rules = filter_rules(
        rules, filter_function=lambda rule: rule.meta.get("att&ck", None)
    )  # select only rules with an att&ck entry specified

    # get malware-related pids if requested by configuration
    malware_pids = None
    if analyze_malware_pids_only:
        malware_pids = get_malware_processes(
                metadata_path=analysis_dir / "metadata.json",
                inject_path=analysis_dir / "inject.log",
                pstree_path=analysis_dir / "process_tree.json",
            )

    # make sure either static or dynamic capability extraction is on
    assert perform_dynamic_analysis or perform_static_analysis

    # extract capabilities from the Drakvuf report
    if perform_dynamic_analysis:
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
    if perform_static_analysis:
        static_capabilities_per_file = static_memory_dumps_capa_analysis(
            analysis_dir, rules, malware_pids=malware_pids
        )

        # create a folder containing the TTPs corresponding to each dump
        dumps_ttp_path = analysis_dir / "dumps_ttp"
        dumps_ttp_path.mkdir(parents=True, exist_ok=True)

        # dump the TTPs for each memdump into a jsonl file
        for dump_name, static_capabilities in static_capabilities_per_file:
            with (dumps_ttp_path / dump_name).open("wb") as f:
                for ttp in construct_ttp_blocks(rules, [static_capabilities]):
                    f.write(orjson.dumps(ttp))
                    f.write(b"\n")


if __name__ == "__main__":
    import sys

    capa_analysis(Path(sys.argv[1]))
