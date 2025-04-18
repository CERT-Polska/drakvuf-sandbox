import { useParams } from "react-router-dom";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getAnalysisProcessTree, getAnalysisStatus } from "./api.js";
import axios, { CanceledError } from "axios";
import { AnalysisStatusBadge } from "./AnalysisStatusBadge.jsx";
import { isStatusPending } from "./analysisStatus.js";
import { AnalysisLiveInteraction } from "./AnalysisLiveInteraction.jsx";
import { ProcessTree } from "./ProcessTree.jsx";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faXmark } from "@fortawesome/free-solid-svg-icons";
import { LazyLog } from "@melloware/react-logviewer";
import { LogViewer } from "./LogViewer.jsx";
import { TabSwitcher } from "./TabSwitcher.jsx";

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

function AnalysisPendingTabs({ analysis }) {
    const tabs = [
        "metadata",
        ...(analysis["vm_id"] ? ["live-interaction"] : []),
    ];
    return (
        <TabSwitcher
            tabIds={tabs}
            getHeader={(tabid) => {
                if (tabid === "metadata") {
                    return "Analysis info";
                } else if (tabid === "live-interaction") {
                    return `Live interaction (vm-${analysis["vm_id"]})`;
                }
            }}
            renderContent={(tabid) => {
                if (tabid === "metadata") {
                    return <AnalysisMetadataTable analysis={analysis} />;
                } else if (tabid === "live-interaction") {
                    return <AnalysisLiveInteraction vmId={analysis["vm_id"]} />;
                }
            }}
        />
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
                            <AnalysisPendingTabs analysis={analysis} />
                        </div>
                    </div>
                </div>
            </div>
        </>
    );
}

function AnalysisLogViewer({ analysisId }) {
    const [inspector, setInspector] = useState(null);
    const tabs = ["apimon", "procmon", "tlsmon", "memdump"];

    const parseLine = useCallback((line) => {
        try {
            const data = JSON.parse(line.trimEnd());
            setInspector(JSON.stringify(data, null, 4));
        } catch (err) {
            setInspector(null);
        }
    }, []);
    return (
        <div>
            <div className="fw-bold py-2">Log type:</div>
            <div className="d-flex align-items-start">
                <TabSwitcher
                    tabIds={tabs}
                    getHeader={(tabId) => tabId}
                    renderContent={(tabId) => {
                        return (
                            <LogViewer
                                analysisId={analysisId}
                                logType={tabId}
                                className="flex-grow-1"
                                onLineClick={parseLine}
                            />
                        );
                    }}
                    tabClassName="flex-column nav-pills me-3"
                    contentClassName="flex-grow-1"
                />
            </div>
            {inspector ? (
                <div>
                    <div
                        className="fw-bold ps-2"
                        style={{ borderTop: "black 1px solid" }}
                    >
                        JSON inspector
                    </div>
                    <pre>{inspector}</pre>
                </div>
            ) : (
                []
            )}
        </div>
    );
}

function AnalysisReportTabs({ analysis }) {
    const [tabIds, setTabIds] = useState(["summary", "logs"]);
    return (
        <div className="card">
            <div className="card-body">
                <TabSwitcher
                    tabIds={tabIds}
                    getHeader={(tabId) => {
                        if (tabId === "summary") {
                            return "Summary";
                        } else if (tabId === "logs") {
                            return "General logs";
                        }
                    }}
                    renderContent={(tabId) => {
                        if (tabId === "summary") {
                            return <div></div>;
                        } else if (tabId === "logs") {
                            return (
                                <AnalysisLogViewer analysisId={analysis.id} />
                            );
                        }
                    }}
                />
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
