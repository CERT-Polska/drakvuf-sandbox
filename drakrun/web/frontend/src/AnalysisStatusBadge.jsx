export function AnalysisStatusBadge({ status, substatus }) {
    const statusStyle =
        {
            queued: "bg-primary",
            started: "bg-info",
            finished: "bg-success",
            failed: "bg-danger",
        }[status] || "bg-secondary";
    return (
        <div className={`badge ${statusStyle} me-2 p-2`}>
            {status}
            {substatus ? ` (${substatus})` : ""}
        </div>
    );
}
