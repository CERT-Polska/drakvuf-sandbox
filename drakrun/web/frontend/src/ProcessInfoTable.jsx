import { formatDate, fromTimestamp } from "./formatUtils.js"

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
                    <td>
                        {Array.isArray(processInfo.args)
                            ? processInfo.args.join(" ")
                            : processInfo.args}
                    </td>
                </tr>
                <tr>
                    <th>Started at</th>
                    <td>
                        {processInfo.ts_from ? (
                            formatDate(fromTimestamp(processInfo.ts_from))
                        ) : (
                            <i>(running from the beginning of analysis)</i>
                        )}
                    </td>
                </tr>
                <tr>
                    <th>Finished at</th>
                    <td>
                        {processInfo.ts_to ? (
                            formatDate(fromTimestamp(processInfo.ts_to))
                        ) : (
                            <i>(never)</i>
                        )}
                    </td>
                </tr>
                {processInfo.exit_code_str ? (
                    <tr>
                        <th>Exit code</th>
                        <td>
                            {processInfo.exit_code_str} (0x
                            {processInfo.exit_code.toString(16)})
                        </td>
                    </tr>
                ) : (
                    []
                )}
            </tbody>
        </table>
    );
}
