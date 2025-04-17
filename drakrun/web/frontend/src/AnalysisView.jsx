import { useParams } from "react-router-dom";
import { useEffect, useState } from "react";
import { getAnalysisList, getAnalysisStatus } from "./api.js";
import { CanceledError } from "axios";
import { AnalysisStatusBadge } from "./AnalysisStatusBadge.jsx";

function TreeNode({ processNode, selectedId, level = 0 }) {}

function ProcessTree() {
    return (
        <ul>
            <li>explorer.exe</li>
        </ul>
    );
}

function AnalysisMetadataTable({ analysis }) {
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
                    <td>{analysis.options["start_command"] || "-"}</td>
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
                    <td>{analysis.options["plugins"] || "-"}</td>
                </tr>
            </tbody>
        </table>
    );
}

function AnalysisLiveInteraction({ vmId }) {}

function AnalysisPendingStatusBox({ children }) {
    return (
        <div className="card">
            <div className="card-body">
                <div className="pb-2">{children}</div>
                <div className="progress">
                    <div
                        className="progress-bar progress-bar-striped progress-bar-animated"
                        role="progressbar"
                        aria-valuenow="100"
                        aria-valuemin="0"
                        aria-valuemax="100"
                        style={{ width: "100%" }}
                    ></div>
                </div>
            </div>
        </div>
    );
}

function AnalysisPendingView({ analysis }) {
    return (
        <>
            <div className="row">
                <div className="col">
                    <AnalysisPendingStatusBox>
                        <div>Please wait until analysis is completed...</div>
                        <div>
                            <div className="me-2 py-2 d-inline-block">
                                Current status:
                            </div>
                            <AnalysisStatusBadge status={analysis.status} />
                        </div>
                    </AnalysisPendingStatusBox>
                </div>
            </div>
            <div className="row py-4">
                <div className="col">
                    <div className="card">
                        <div className="card-body">
                            <nav>
                                <div
                                    className="nav nav-tabs"
                                    id="nav-tab"
                                    role="tablist"
                                >
                                    <button
                                        className="nav-link active"
                                        data-bs-toggle="tab"
                                        data-bs-target="#nav-metadata"
                                        type="button"
                                        role="tab"
                                        aria-controls="nav-home"
                                        aria-selected="true"
                                    >
                                        Analysis info
                                    </button>
                                    {analysis["vm_id"] ? (
                                        <button
                                            className="nav-link"
                                            data-bs-toggle="tab"
                                            data-bs-target="#nav-live-interaction"
                                            type="button"
                                            role="tab"
                                            aria-controls="nav-profile"
                                            aria-selected="false"
                                        >
                                            Live interaction (vm-
                                            {analysis["vm_id"]})
                                        </button>
                                    ) : (
                                        []
                                    )}
                                </div>
                            </nav>
                            <div className="tab-content" id="nav-tabContent">
                                <div
                                    className="tab-pane fade show active"
                                    id="nav-metadata"
                                    role="tabpanel"
                                >
                                    <AnalysisMetadataTable
                                        analysis={analysis}
                                    />
                                </div>
                                {analysis["vm_id"] ? (
                                    <div
                                        className="tab-pane fade"
                                        id="nav-live-interaction"
                                        role="tabpanel"
                                    ></div>
                                ) : (
                                    []
                                )}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </>
    );
}

function AnalysisReport({ analysisId }) {
    const [analysisInfo, setAnalysisInfo] = useState();
    const [error, setError] = useState();

    useEffect(() => {
        const abortController = new AbortController();
        getAnalysisStatus({ analysisId, abortController })
            .then((response) => {
                setAnalysisInfo(response);
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
    }, [analysisId]);

    if (typeof error !== "undefined") {
        return <div>Error: {error.toString()}</div>;
    }

    if (typeof analysisInfo === "undefined") {
        return (
            <div className="row">
                <div className="col">
                    <AnalysisPendingStatusBox>
                        Fetching analysis status...
                    </AnalysisPendingStatusBox>
                </div>
            </div>
        );
    }

    return <AnalysisPendingView analysis={analysisInfo} />;
}

export default function AnalysisView() {
    const { jobid } = useParams();
    return (
        <div className="container-fluid px-4">
            <h1 className="m-4 h4">Analysis report</h1>
            <AnalysisReport analysisId={jobid} />
        </div>
    );
}
