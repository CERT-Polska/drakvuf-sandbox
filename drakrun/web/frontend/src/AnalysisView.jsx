import { useParams } from "react-router-dom";
import { useCallback, useEffect, useRef, useState } from "react";
import { getAnalysisProcessTree, getAnalysisStatus } from "./api.js";
import axios, { CanceledError } from "axios";
import { AnalysisStatusBadge } from "./AnalysisStatusBadge.jsx";
import { isStatusPending } from "./analysisStatus.js";
import { AnalysisLiveInteraction } from "./AnalysisLiveInteraction.jsx";
import { ProcessTree } from "./ProcessTree.jsx";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faXmark } from "@fortawesome/free-solid-svg-icons";
import { LazyLog } from "@melloware/react-logviewer";

function isProcessInteresting(process) {
    return process.procname.endsWith("explorer.exe");
}

function getInterestingProcesses(processTree) {
    let activeSet = new Set();
    for (let process of processTree) {
        if (isProcessInteresting(process)) {
            activeSet.add(process.seqid);
        }
        if (process.children.length > 0) {
            const activeChildren = getInterestingProcesses(process.children);
            if (activeChildren.size) {
                activeSet = activeSet.union(activeChildren);
                activeSet.add(process.seqid);
            }
        }
    }
    return activeSet;
}

function ProcessTreeView({ analysisId }) {
    const [uncollapsed, setUncollapsed] = useState(new Set());
    const [processTree, setProcessTree] = useState();
    const [error, setError] = useState();

    useEffect(() => {
        getAnalysisProcessTree({ analysisId })
            .then((data) => {
                setProcessTree(data);
                setUncollapsed(getInterestingProcesses(data));
            })
            .catch((e) => {
                console.error(e);
                setError(e);
            });
    }, []);

    return (
        <div className="card">
            <div className="card-body">
                {typeof processTree === "undefined" ? (
                    <span>Loading process tree...</span>
                ) : (
                    []
                )}
                {typeof error !== "undefined" ? (
                    <span className="text-danger">
                        Unable to load process tree
                    </span>
                ) : (
                    []
                )}
                {typeof processTree !== "undefined" ? (
                    <ProcessTree
                        processTree={processTree}
                        uncollapsedSeqid={uncollapsed}
                        setCollapse={(seqid) => {
                            const collapse = uncollapsed.has(seqid);
                            setUncollapsed((currentValue) => {
                                let newSet = new Set(currentValue);
                                if (!collapse) {
                                    newSet.add(seqid);
                                } else {
                                    newSet.delete(seqid);
                                }
                                return newSet;
                            });
                        }}
                    />
                ) : (
                    []
                )}
            </div>
        </div>
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
    const [currentTab, setCurrentTab] = useState("home");
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
                                        className={`nav-link ${currentTab === "home" ? "active" : ""}`}
                                        type="button"
                                        role="tab"
                                        onClick={() => setCurrentTab("home")}
                                    >
                                        Analysis info
                                    </button>
                                    {analysis["vm_id"] ? (
                                        <button
                                            className={`nav-link ${currentTab === "live-interaction" ? "active" : ""}`}
                                            type="button"
                                            role="tab"
                                            aria-controls="nav-live-interaction"
                                            aria-selected={
                                                currentTab ===
                                                "live-interaction"
                                            }
                                            onClick={() =>
                                                setCurrentTab(
                                                    "live-interaction",
                                                )
                                            }
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
                                {currentTab === "home" ? (
                                    <div
                                        className="tab-pane active"
                                        role="tabpanel"
                                    >
                                        <AnalysisMetadataTable
                                            analysis={analysis}
                                        />
                                    </div>
                                ) : (
                                    []
                                )}
                                {currentTab === "live-interaction" &&
                                analysis["vm_id"] ? (
                                    <div
                                        className="tab-pane active"
                                        role="tabpanel"
                                    >
                                        <AnalysisLiveInteraction
                                            vmId={analysis["vm_id"]}
                                        />
                                    </div>
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

function AnalysisReportTabs({ analysis }) {
    const [currentTab, setCurrentTab] = useState("home");
    return (
        <div className="card">
            <div className="card-body">
                <nav>
                    <div className="nav nav-tabs" id="nav-tab" role="tablist">
                        <button
                            className={`nav-link ${currentTab === "home" ? "active" : ""}`}
                            type="button"
                            role="tab"
                            onClick={() => setCurrentTab("home")}
                        >
                            Summary
                        </button>
                        <button
                            className={`nav-link ${currentTab === "home" ? "active" : ""}`}
                            type="button"
                            role="tab"
                            onClick={() => setCurrentTab("home")}
                        >
                            General logs
                        </button>
                        <button
                            className={`nav-link ${currentTab === "home" ? "active" : ""}`}
                            type="button"
                            role="tab"
                            onClick={() => setCurrentTab("home")}
                        >
                            Procdot graph
                        </button>
                        <button
                            className={`nav-link ${currentTab === "home" ? "active" : ""}`}
                            type="button"
                            role="tab"
                            onClick={() => setCurrentTab("home")}
                        >
                            <span>Process powershell.exe (6012)</span>
                            <FontAwesomeIcon icon={faXmark} className="ms-2" />
                        </button>
                    </div>
                </nav>
                <div className="tab-content" id="nav-tabContent">
                    ...
                </div>
            </div>
        </div>
    );
}

function AnalysisReport({ analysis }) {
    return (
        <>
            <div className="row">
                <div className="col-6">
                    <ProcessTreeView analysisId={analysis.id} />
                </div>
                <div className="col-6">
                    <AnalysisMetadataTable analysis={analysis} />
                </div>
            </div>
            <div className="row py-4">
                <div className="col">
                    <AnalysisReportTabs analysis={analysis} />
                </div>
            </div>
        </>
    );
}

function AnalysisViewComponent({ analysisId }) {
    const checkInterval = useRef(null);
    const [analysisInfo, setAnalysisInfo] = useState();
    const [error, setError] = useState();

    const checkStatus = useCallback(() => {
        getAnalysisStatus({ analysisId })
            .then((response) => {
                setAnalysisInfo(response);
                if (isStatusPending(response?.status)) {
                    if (!checkInterval.current)
                        checkInterval.current = setTimeout(() => {
                            checkInterval.current = null;
                            checkStatus();
                        }, 1000);
                }
            })
            .catch((error) => {
                if (!(error instanceof CanceledError)) {
                    setError(error);
                    console.error(error);
                }
            });
    }, [analysisId]);

    useEffect(() => {
        checkStatus();
        return () => {
            if (checkInterval.current) {
                clearTimeout(checkInterval.current);
                checkInterval.current = null;
            }
        };
    }, [analysisId, checkStatus]);

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
    if (isStatusPending(analysisInfo?.status)) {
        return <AnalysisPendingView analysis={analysisInfo} />;
    }
    return <AnalysisReport analysis={analysisInfo} />;
}

export default function AnalysisView() {
    const { jobid } = useParams();
    return (
        <div className="container-fluid px-4">
            <h1 className="m-4 h4">Analysis report</h1>
            <AnalysisViewComponent analysisId={jobid} />
        </div>
    );
}
