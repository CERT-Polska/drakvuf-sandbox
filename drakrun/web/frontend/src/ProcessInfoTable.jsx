function epochToTimestamp(timestamp) {
    return new Date(timestamp * 1000).toISOString();
}

export function ProcessInfoTable({ processInfo }) {
    return (
        <table className="datatable-table">
            <tbody>
                <tr>
                    <th>Process name</th>
                    <td>{processInfo.procname}</td>
                </tr>
                <tr>
                    <th>PID</th>
                    <td>{processInfo.pid}</td>
                </tr>
                <tr>
                    <th>PPID</th>
                    <td>{processInfo.ppid}</td>
                </tr>
                <tr>
                    <th>Arguments</th>
                    <td>{Array.isArray(processInfo.args) ? processInfo.args.join(" ") : processInfo.args}</td>
                </tr>
                <tr>
                    <th>Started at</th>
                    <td>
                        {processInfo.ts_from ? (
                            epochToTimestamp(processInfo.ts_from)
                        ) : (
                            <i>(running from the beginning of analysis)</i>
                        )}
                    </td>
                </tr>
                <tr>
                    <th>Finished at</th>
                    <td>
                        {processInfo.ts_to ? (
                            epochToTimestamp(processInfo.ts_to)
                        ) : (
                            <i>(never)</i>
                        )}
                    </td>
                </tr>
            </tbody>
        </table>
    );
}
