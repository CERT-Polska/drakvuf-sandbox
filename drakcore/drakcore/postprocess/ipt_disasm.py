import os
import argparse
import json
import pprint
from pathlib import Path
from functools import reduce
from collections import defaultdict
import subprocess
import tempfile

from karton2 import Task, RemoteResource
from typing import Dict
from drakcore.postprocess.ipt_utils import log, load_drakvuf_output, get_fault_va, get_fault_pa, get_trap_pa, get_frame_va, page_align, is_page_aligned, select_cr3, hexint
from zipfile import ZipFile


def debug_faults(page_faults):
    faulted_pages = sorted(set(page_align((get_fault_va(fault))) for fault in page_faults))

    ranges = []
    current = []
    for a, b in zip(faulted_pages, faulted_pages[1:]):
        current.append(a)
        if (b - a) == 0x1000:
            continue
        else:
            ranges.append(current)
            current = []

    for chunk in ranges:
        beg = chunk[0]
        end = chunk[-1] + 0xfff
        length = (end + 1 - beg) / 0x1000
        log.debug("%#016x - %#016x (%d pages)", beg, end, length)


def build_frame_va_map(frames):
    frame_map = defaultdict(list)
    for frame in frames:
        addr = page_align(get_frame_va(frame))
        frame_map[addr].append(frame)
    return frame_map


def select_frame(frames, phys_addr):
    for frame in frames:
        if phys_addr == page_align(get_trap_pa(frame)):
            return frame
    return None


def match_frames(page_faults, frames, foreign_frames):
    log.info("Matching frames for each fault")

    frame_map = build_frame_va_map(frames)
    foreign_frame_map = build_frame_va_map(foreign_frames)

    unresolved = 0
    foreign_resolved = 0
    results = []

    for fault in page_faults:
        va = get_fault_va(fault)
        pa = get_fault_pa(fault)

        va_page = page_align(va)
        pa_page = page_align(pa)

        frame = select_frame(frame_map[va_page], pa_page)

        if frame is None:
            frame = select_frame(foreign_frame_map[va_page], pa_page)
            if frame is None:
                unresolved += 1
            else:
                foreign_resolved += 1
        log.info("%#016x -> %s", va_page, frame['FrameFile'] if frame else "?")
        if frame:
            results.append((va_page, frame['FrameFile']))

    log.info("Failed to resolve %d faults. Let's hope they're not related to code", unresolved)
    log.info("Resolved %d from external CR3", foreign_resolved)

    return results


def main(analysis_dir, cr3_value):
    log.debug("Analysis directory: %s", analysis_dir)
    log.debug("CR3: %#x", cr3_value)

    if not is_page_aligned(cr3_value):
        log.critical("CR3 must be aligned to page! Got %#x", cr3_value)
        return

    page_faults = load_drakvuf_output(analysis_dir / "pagefault.log")
    executed_frames = load_drakvuf_output(analysis_dir / "execframe.log")

    faults_in_process = list(select_cr3(lambda cr3: cr3 == cr3_value, page_faults))
    frames_in_process = list(select_cr3(lambda cr3: cr3 == cr3_value, executed_frames))
    frames_out_process = list(select_cr3(lambda cr3: cr3 != cr3_value, executed_frames))

    log.info("%d frames dumped from this process", len(frames_in_process))
    log.info("%d frames outside this process", len(frames_out_process))
    log.info("%d faults in process", len(faults_in_process))

    faults_in_process.sort(key=get_fault_va)
    debug_faults(faults_in_process)
    mappings = match_frames(faults_in_process, frames_in_process, frames_out_process)

    pages = []
    for addr, fname in mappings:
        name = Path(fname).name
        fpath = analysis_dir / "ipt" / "frames" / name
        if fpath.stat().st_size == 0x1000:
            pages.append("--raw")
            pages.append(f"{fpath}:0x{addr:x}")
    ptxed_cmdline = [
        "/opt/libipt/bin/ptxed",
        "--block-decoder",
        "--pt",
        os.path.join(analysis_dir, "ipt", "ipt_stream_vcpu0"),
        *pages
    ]

    log.info("IPT: Succesfully generated ptxed command line")
    # TODO automatically call ptxed in the future(?)
    return subprocess.list2cmdline(ptxed_cmdline)


def generate_ipt_disasm(task: Task, resources: Dict[str, RemoteResource], minio):
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        resources["inject.log"].download_to_file(str(tmpdir / "inject.log"))

        with open(str(tmpdir / "inject.log"), "r") as f:
            inject_log = json.loads(f.read().split('\n')[0].strip())

        injected_pid = inject_log["InjectedPid"]
        resources["execframe.log"].download_to_file(str(tmpdir / "execframe.log"))

        with open(str(tmpdir / "execframe.log"), "r") as f:
            for line in f:
                obj = json.loads(line)

                if obj.get("PID") == injected_pid:
                    injected_cr3 = hexint(obj["CR3"])
                    break
            else:
                log.error("Failed to find injected process' CR3, not doing IPT disasm")
                return

        resources["pagefault.log"].download_to_file(str(tmpdir / "pagefault.log"))
        resources["execframe.log"].download_to_file(str(tmpdir / "execframe.log"))

        with resources["ipt.zip"].download_temporary_file() as ipt_zip_tmp:
            with ZipFile(ipt_zip_tmp) as ipt_zip:
                ipt_zip.extractall(tmpdir)

        main(tmpdir, injected_cr3)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("analysis_dir", help="Analysis output directory")
    parser.add_argument("cr3_value", type=hexint, help="CR3 of process of interest")
    args = parser.parse_args()

    analysis_dir = Path(args.analysis_dir)
    cr3_value = args.cr3_value

    ptxed_cmdline = main(analysis_dir, cr3_value)
    print(ptxed_cmdline)
