import argparse
import logging
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

from drakrun.lib.paths import IPT_DIR

from .ipt_utils import (
    get_fault_pa,
    get_fault_va,
    get_frame_va,
    get_trap_pa,
    hexint,
    is_page_aligned,
    load_drakvuf_output,
    log,
    page_align,
    select_cr3,
)


def debug_faults(page_faults):
    faulted_pages = sorted(
        set(page_align((get_fault_va(fault))) for fault in page_faults)
    )

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
        end = chunk[-1] + 0xFFF
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
        log.info("%#016x -> %s", va_page, frame["DumpFile"] if frame else "?")
        if frame:
            results.append((va_page, frame["DumpFile"]))

    log.info(
        "Failed to resolve %d faults. Let's hope they're not related to code",
        unresolved,
    )
    log.info("Resolved %d from external CR3", foreign_resolved)

    return results


def get_ptxed_cmdline(analysis_dir, cr3_value, vcpu, use_blocks=False):
    log.debug("Analysis directory: %s", analysis_dir)
    log.debug("CR3: %#x", cr3_value)

    if not is_page_aligned(cr3_value):
        log.critical("CR3 must be aligned to page! Got %#x", cr3_value)
        return

    codemon_out = load_drakvuf_output(analysis_dir / "codemon.log")
    page_faults = [obj for obj in codemon_out if obj["EventType"] == "pagefault"]
    executed_frames = [obj for obj in codemon_out if obj["EventType"] == "execframe"]

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
        if fname == "(null)":
            # codemon failed to save dump
            continue
        name = Path(fname).name
        fpath = analysis_dir / IPT_DIR / "dumps" / name
        if fpath.stat().st_size == 0x1000:
            pages.append("--raw")
            pages.append(f"{fpath}:0x{addr:x}")

    binary = ["ptxed", "--block-decoder"]

    if use_blocks:
        binary = ["drak-ipt-blocks", "--cr3", hex(cr3_value)]

    ptxed_cmdline = binary + pages
    log.info("IPT: Succesfully generated ptxed command line")
    return ptxed_cmdline


def cmdline_main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Print generated ptxed command, don't run it",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Print additional debug messages",
    )
    parser.add_argument(
        "--blocks",
        action="store_true",
        default=False,
        help="Use drak-ipt-blocks instead of ptxed",
    )
    parser.add_argument(
        "--analysis", help="Analysis directory (as downloaded from MinIO)"
    )
    parser.add_argument("--cr3", type=hexint, help="CR3 of process of interest")
    parser.add_argument("--vcpu", type=int, help="Number of vCPU to disassemble")
    args = parser.parse_args()

    if not args.dry_run:
        log.setLevel(logging.WARNING)

    analysis_dir = Path(args.analysis)
    cr3_value = args.cr3

    ptxed_cmdline = get_ptxed_cmdline(analysis_dir, cr3_value, args.vcpu, args.blocks)

    if args.dry_run:
        print(subprocess.list2cmdline(ptxed_cmdline + ["--pt", "FILTERED_PT_FILE"]))
        sys.exit(0)

    with tempfile.NamedTemporaryFile() as f:
        filter_cmdline = [
            f"drak-ipt-filter {analysis_dir}/ipt/ipt_stream_vcpu{args.vcpu} {args.cr3}"
        ]

        if args.verbose:
            filter_cmdline.append("pv")

        filter_cmdline.append(f"cat > {f.name}")

        logging.info(f"Filtering IPT stream for CR3: {args.cr3}")
        subprocess.run(" | ".join(filter_cmdline), shell=True)

        logging.info("Generating trace disassembly")
        ptxed_cmdline = ptxed_cmdline + ["--pt", f.name]
        subprocess.run(ptxed_cmdline)
