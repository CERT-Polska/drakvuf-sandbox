export function AnalysisPriorityBadge({ priority }) {
    const priorityStyle =
        {
            low: "bg-secondary",
            normal: "bg-light text-dark",
            high: "bg-warning text-dark",
        }[priority] || "bg-light text-dark";
    return (
        <div className={`badge ${priorityStyle} me-2 p-2`}>
            {priority || "normal"}
        </div>
    );
}
