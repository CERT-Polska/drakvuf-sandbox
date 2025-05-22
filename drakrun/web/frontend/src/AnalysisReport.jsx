import { useCallback, useEffect, useState } from "react";
import { getAnalysisProcessTree, getLog, getLogList } from "./api.js";
import { ProcessTree } from "./ProcessTree.jsx";
import { TabSwitcher, Tab, useTabContext } from "./TabSwitcher.jsx";
import { getLogLoader, LogViewer } from "./LogViewer.jsx";
import { AnalysisMetadataTable } from "./AnalysisMetadataTable.jsx";
import { AnalysisScreenshotViewer } from "./AnalysisScreenshotViewer.jsx";

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

export function AnalysisLogViewerTab({ analysisId }) {
    const logType = useTabContext()?.activeTab;
    const logLoaderFactory = useCallback(() => {
        return getLogLoader({
            getLogEntries: ({ rangeStart, rangeEnd }) =>
                getLog({ analysisId, logType, rangeStart, rangeEnd }),
        });
    }, [analysisId, logType]);
    if (!logType) return [];
    return <LogViewer logLoaderFactory={logLoaderFactory} />;
}

function AnalysisLogViewer({ analysisId }) {
    const [tabs, setTabs] = useState();
    const [activeTab, setActiveTab] = useState();
    const [error, setError] = useState();
    const loadLogTypes = useCallback(async () => {
        try {
            const logTypes = await getLogList({ analysisId });
            const tabs = logTypes
                .filter((logType) => logType.endsWith(".log"))
                .map((logType) => logType.split(".")[0]);
            setTabs(tabs);
            setActiveTab(tabs[0]);
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
                    tabs={tabs}
                    activeTab={activeTab}
                    onTabSwitch={setActiveTab}
                    tabClassName="flex-column nav-pills me-3"
                    contentClassName="flex-grow-1"
                >
                    <AnalysisLogViewerTab analysisId={analysisId} />
                </TabSwitcher>
            </div>
        </div>
    );
}

function AnalysisReportTabs({ analysis }) {
    const [activeTab, setActiveTab] = useState("General logs");
    return (
        <div className="card">
            <div className="card-body">
                <TabSwitcher activeTab={activeTab} onTabSwitch={setActiveTab}>
                    <Tab tab="General logs">
                        <AnalysisLogViewer analysisId={analysis.id} />
                    </Tab>
                    {analysis.screenshots ? (
                        <Tab tab="Screenshots">
                            <AnalysisScreenshotViewer analysis={analysis} />
                        </Tab>
                    ) : null}
                </TabSwitcher>
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
