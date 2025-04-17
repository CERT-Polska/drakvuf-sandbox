export function AnalysisStatusBadge({ status }) {
    const statusStyle =
        {
            queued: "bg-primary",
            started: "bg-info",
            finished: "bg-success",
            failed: "bg-danger",
        }[status] || "bg-secondary";
    return <div className={`badge ${statusStyle} me-2 p-2`}>{status}</div>;
}
