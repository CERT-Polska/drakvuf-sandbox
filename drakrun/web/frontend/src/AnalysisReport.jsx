import { useCallback, useEffect, useState } from "react";
import { getAnalysisProcessTree, getLogList } from "./api.js";
import { ProcessTree } from "./ProcessTree.jsx";
import { TabSwitcher } from "./TabSwitcher.jsx";
import { LogViewer } from "./LogViewer.jsx";
import { AnalysisMetadataTable } from "./AnalysisMetadataTable.jsx";

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
    const [selected, setSelected] = useState();
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
                        selected={selected}
                        onSelect={(seqid) => {
                            setSelected(seqid);
                        }}
                    />
                ) : (
                    []
                )}
            </div>
        </div>
    );
}

function AnalysisLogViewer({ analysisId }) {
    const [inspector, setInspector] = useState(null);
    const [tabs, setTabs] = useState();
    const [error, setError] = useState();
    const parseLine = useCallback((line) => {
        try {
            const data = JSON.parse(line.trimEnd());
            setInspector(JSON.stringify(data, null, 4));
        } catch (err) {
            setInspector(null);
        }
    }, []);

    const loadLogTypes = useCallback(async () => {
        try {
            const logTypes = await getLogList({ analysisId });
            setTabs(
                logTypes
                    .filter((logType) => logType.endsWith(".log"))
                    .map((logType) => logType.split(".")[0]),
            );
        } catch (err) {
            setError(err);
            console.error(err);
        }
    }, [analysisId]);

    useEffect(() => {
        loadLogTypes();
    }, [analysisId]);

    if (typeof tabs === "undefined") {
        return <div>Loading log information...</div>;
    }

    if (typeof error !== "undefined") {
        return <div className="text-danger">Error: {error.toString()}</div>;
    }

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
    return (
        <div className="card">
            <div className="card-body">
                <TabSwitcher
                    tabIds={["general-logs"]}
                    getHeader={(tabId) => {
                        if (tabId === "summary") {
                            return "Summary";
                        } else if (tabId === "process-logs") {
                            return "Process logs";
                        } else if (tabId === "general-logs") {
                            return "General logs";
                        }
                    }}
                    renderContent={(tabId) => {
                        if (tabId === "general-logs") {
                            return (
                                <AnalysisLogViewer analysisId={analysis.id} />
                            );
                        } else {
                            return <div>(not implemented)</div>;
                        }
                    }}
                />
            </div>
        </div>
    );
}

export function AnalysisReport({ analysis }) {
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
