import { PluginList } from "./PluginPicker.jsx";

export function AnalysisMetadataTable({ analysis }) {
    return (
        <table className="datatable-table">
            <tbody>
                <tr>
                    <th>File name</th>
                    <td>{analysis.file.name}</td>
                </tr>
                <tr>
                    <th>SHA256</th>
                    <td>{analysis.file.sha256}</td>
                </tr>
                <tr>
                    <th>Type</th>
                    <td>{analysis.file.type}</td>
                </tr>
                <tr>
                    <th>Start command</th>
                    <td>
                        {(analysis.options["start_command"] || ["-"]).join(" ")}
                    </td>
                </tr>
                <tr>
                    <th>Analysis time</th>
                    <td>{analysis.options["timeout"]} seconds</td>
                </tr>
                <tr>
                    <th>Started at</th>
                    <td>{analysis["time_started"] || "-"}</td>
                </tr>
                <tr>
                    <th>Finished at</th>
                    <td>{analysis["time_finished"] || "-"}</td>
                </tr>
                <tr>
                    <th>Plugins</th>
                    <td>
                        <PluginList plugins={analysis.options["plugins"]} />
                    </td>
                </tr>
            </tbody>
        </table>
    );
}
