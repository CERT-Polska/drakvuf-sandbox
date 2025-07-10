import { useCallback, useEffect, useState } from "react";
import { getLog, getLogList, getProcessInfo, getProcessLog } from "./api.js";
import { TabSwitcher, Tab, useTabContext } from "./TabSwitcher.jsx";
import { getLogLoader, LogViewer } from "./LogViewer.jsx";
import { AnalysisMetadataTable } from "./AnalysisMetadataTable.jsx";
import { AnalysisScreenshotViewer } from "./AnalysisScreenshotViewer.jsx";
import { ProcessTreeView } from "./ProcessTreeView.jsx";
import { MethodFilterPicker } from "./MethodFilterPicker.jsx";
import { ProcessInfoTable } from "./ProcessInfoTable.jsx";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faDownload } from "@fortawesome/free-solid-svg-icons";
import axios from "axios";

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
        return <div className="py-2">Loading log information...</div>;
    }

    if (typeof error !== "undefined") {
        return (
            <div className="text-danger py-2">Error: {error.toString()}</div>
        );
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

function ProcessInfoTab({ analysisId, selectedProcess, processInfo }) {
    const activeTab = useTabContext()?.activeTab;
    if (activeTab !== "Process information") {
        return [];
    }
    return <ProcessInfoTable processInfo={processInfo["process"]} />;
}

function ProcessLogViewerTab({ analysisId, selectedProcess, processInfo }) {
    const [methodsFilter, setMethodsFilter] = useState([]);
    const activeTab = useTabContext()?.activeTab;
    const logType =
        activeTab === "Process information" || !processInfo["logs"][activeTab]
            ? undefined
            : activeTab;
    const logMethods = logType ? processInfo["logs"][logType] : [];
    const logLoaderFactory = useCallback(() => {
        return getLogLoader({
            getLogEntries: ({ rangeStart, rangeEnd }) => {
                return getProcessLog({
                    analysisId,
                    logType,
                    selectedProcess,
                    rangeStart,
                    rangeEnd,
                    methodsFilter,
                });
            },
        });
    }, [analysisId, logType, selectedProcess, methodsFilter]);
    useEffect(() => {
        setMethodsFilter([]);
    }, [logType]);
    if (!logType) return [];
    return (
        <>
            <div>
                <label className="form-label">Method filter</label>
                <MethodFilterPicker
                    onFilterChange={setMethodsFilter}
                    currentFilter={methodsFilter}
                    methods={logMethods}
                />
            </div>
            <LogViewer logLoaderFactory={logLoaderFactory} />
        </>
    );
}

function ProcessLogViewer({ analysisId, selectedProcess }) {
    const [tabs, setTabs] = useState();
    const [activeTab, setActiveTab] = useState();
    const [processInfo, setProcessInfo] = useState();
    const [error, setError] = useState();
    const loadProcessInfo = useCallback(
        async (processSeqId) => {
            try {
                const processInfo = await getProcessInfo({
                    analysisId,
                    processSeqId,
                });
                const tabs = Object.keys(processInfo["logs"]);
                setProcessInfo(processInfo);
                setTabs(["Process information", ...tabs]);
                setActiveTab("Process information");
            } catch (err) {
                setError(err);
                console.error(err);
            }
        },
        [analysisId],
    );

    useEffect(() => {
        if (typeof selectedProcess === "undefined") return;
        loadProcessInfo(selectedProcess);
    }, [analysisId, selectedProcess]);

    if (typeof selectedProcess === "undefined") {
        return (
            <div className="fw-bold py-2">
                Select a process from the process tree above
            </div>
        );
    }

    if (typeof tabs === "undefined") {
        return <div className="py-2">Loading log information...</div>;
    }

    if (typeof error !== "undefined") {
        return (
            <div className="text-danger py-2">Error: {error.toString()}</div>
        );
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
                    <ProcessInfoTab
                        analysisId={analysisId}
                        selectedProcess={selectedProcess}
                        processInfo={processInfo}
                    />
                    <ProcessLogViewerTab
                        analysisId={analysisId}
                        selectedProcess={selectedProcess}
                        processInfo={processInfo}
                    />
                </TabSwitcher>
            </div>
        </div>
    );
}

function AnalysisReportTabs({ analysis, selectedProcess }) {
    const [activeTab, setActiveTab] = useState("General logs");
    return (
        <div className="card">
            <div className="card-body">
                <TabSwitcher activeTab={activeTab} onTabSwitch={setActiveTab}>
                    <Tab tab="General logs">
                        <AnalysisLogViewer analysisId={analysis.id} />
                    </Tab>
                    <Tab tab="Process logs">
                        <ProcessLogViewer
                            analysisId={analysis.id}
                            selectedProcess={selectedProcess}
                        />
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
    const [selectedProcess, setSelectedProcess] = useState();
    const plugins = analysis.options?.plugins;
    const baseUrl = axios.defaults.baseURL;
    return (
        <>
            <div className="row">
                <div className="col-6">
                    <ProcessTreeView
                        analysisId={analysis.id}
                        selectedProcess={selectedProcess}
                        onProcessSelect={setSelectedProcess}
                    />
                </div>
                <div className="col-6">
                    <AnalysisMetadataTable analysis={analysis} />
                    <div className="card">
                        <div className="card-body">
                            <a href={`${baseUrl}/pcap_file/${analysis.id}`}>
                                <button className="btn btn-primary me-2">
                                    <FontAwesomeIcon
                                        icon={faDownload}
                                        className="me-2"
                                    />
                                    Download PCAP
                                </button>
                            </a>
                            {Array.isArray(plugins) &&
                            plugins.includes("tlsmon") ? (
                                <a href={`${baseUrl}/pcap_keys/${analysis.id}`}>
                                    <button className="btn btn-primary me-2">
                                        <FontAwesomeIcon
                                            icon={faDownload}
                                            className="me-2"
                                        />
                                        TLS keys
                                    </button>
                                </a>
                            ) : (
                                []
                            )}
                            {Array.isArray(plugins) &&
                            plugins.includes("memdump") ? (
                                <a href={`${baseUrl}/dumps/${analysis.id}`}>
                                    <button className="btn btn-primary me-2">
                                        <FontAwesomeIcon
                                            icon={faDownload}
                                            className="me-2"
                                        />
                                        Memory dumps
                                    </button>
                                </a>
                            ) : (
                                []
                            )}
                        </div>
                    </div>
                </div>
            </div>
            <div className="row py-4">
                <div className="col">
                    <AnalysisReportTabs
                        analysis={analysis}
                        selectedProcess={selectedProcess}
                    />
                </div>
            </div>
        </>
    );
}
