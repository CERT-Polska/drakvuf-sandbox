import { useCallback, useEffect, useState } from "react";
import { getLog, getLogList } from "./api.js";
import { TabSwitcher, Tab, useTabContext } from "./TabSwitcher.jsx";
import { getLogLoader, LogViewer } from "./LogViewer.jsx";
import { AnalysisMetadataTable } from "./AnalysisMetadataTable.jsx";
import { AnalysisScreenshotViewer } from "./AnalysisScreenshotViewer.jsx";
import { ProcessTreeView } from "./ProcessTreeView.jsx";

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
    const [selectedProcess, setSelectedProcess] = useState();
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
