import { Link } from "react-router-dom";
import { useEffect, useState } from "react";
import { getAnalysisList } from "./api";
import { CanceledError } from "axios";
import { AnalysisStatusBadge } from "./AnalysisStatusBadge.jsx";

function AnalysisListRow({ analysis }) {
    return (
        <tr>
            <td>
                <AnalysisStatusBadge status={analysis.status} />
                <Link to={`/analysis/${analysis.id}`}>{analysis.id}</Link>
            </td>
            <td>
                <div className="d-flex flex-row flex-wrap font-monospace">
                    <div className="fw-bold pe-2">SHA256:</div>
                    <div>{analysis.file.sha256}</div>
                </div>
                <div className="d-flex flex-row flex-wrap font-monospace">
                    <div className="fw-bold pe-2">Name:</div>
                    <div>{analysis.file.name}</div>
                </div>
                <div className="d-flex flex-row flex-wrap">
                    <div className="fw-bold pe-2">Type:</div>
                    <div>{analysis.file.type}</div>
                </div>
            </td>
            <td>{analysis.time_started || "-"}</td>
            <td>{analysis.time_finished || "-"}</td>
        </tr>
    );
}

function AnalysisListTable() {
    const [error, setError] = useState();
    const [analysisList, setAnalysisList] = useState();

    useEffect(() => {
        const abortController = new AbortController();
        getAnalysisList({ abortController })
            .then((response) => {
                setAnalysisList(response);
            })
            .catch((error) => {
                if (!(error instanceof CanceledError)) {
                    setError(error);
                    console.error(error);
                }
            });
        return () => {
            abortController.abort();
        };
    }, []);

    if (typeof error !== "undefined") {
        return <div>Error: {error.toString()}</div>;
    }

    if (typeof analysisList === "undefined") {
        return <div>Loading...</div>;
    }

    if (analysisList.length === 0) {
        return (
            <div>There are no analyses. Upload sample to create a new one.</div>
        );
    }

    return (
        <div className="datatable-container">
            <table className="datatable-table">
                <thead>
                    <tr>
                        <th>Analysis ID</th>
                        <th>Sample info</th>
                        <th>Started</th>
                        <th>Finished</th>
                    </tr>
                </thead>
                <tbody>
                    {analysisList.map((analysis) => (
                        <AnalysisListRow
                            analysis={analysis}
                            key={analysis.id}
                        />
                    ))}
                </tbody>
            </table>
        </div>
    );
}

export default function AnalysisList() {
    return (
        <div className="container-fluid px-4">
            <h1 className="m-4 h4">Analyses</h1>
            <AnalysisListTable />
        </div>
    );
}
