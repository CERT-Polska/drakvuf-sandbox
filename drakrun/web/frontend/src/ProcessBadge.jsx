function trimProcessName(procname) {
    return procname.split("\\").at(-1);
}

export function ProcessBadge({ process, onClick = () => {} }) {
    if (!process) {
        return [];
    }
    return (
        <button
            className="btn btn-inline-link fw-lighter border rounded px-2 ms-2"
            onClick={onClick}
        >
            {trimProcessName(process.name)}:{process.pid}
        </button>
    );
}
