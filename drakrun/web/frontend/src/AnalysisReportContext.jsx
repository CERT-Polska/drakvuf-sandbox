import React, { useContext, useMemo } from "react";
import {
    getAnalysisSummary,
    getProcessInfo,
    getAnalysisProcessTree,
} from "./api.js";

const AnalysisReportContext = React.createContext({});

let BASE_URL = "";
if (import.meta.env.VITE_API_SERVER) {
    BASE_URL = import.meta.env.VITE_API_SERVER;
} else {
    BASE_URL = "/api";
}

export function useAnalysisReport() {
    return useContext(AnalysisReportContext);
}

export function OnlineAnalysisReportProvider({ analysisInfo, children }) {
    const contextValue = useMemo(
        () => ({
            analysisInfo,
            getAnalysisSummary,
            getProcessInfo,
            getAnalysisProcessTree,
            getScreenshotURL: (analysis_id, screenshot_idx) =>
                `${BASE_URL}/screenshot/${analysis_id}/${screenshot_idx}`,
            isOffline: false,
        }),
        [analysisInfo],
    );
    return (
        <AnalysisReportContext.Provider value={contextValue}>
            {children}
        </AnalysisReportContext.Provider>
    );
}

export function OfflineAnalysisReportProvider({ reportData, children }) {
    const contextValue = useMemo(
        () => ({
            analysisInfo: reportData["metadata.json"],
            getAnalysisSummary: () =>
                new Promise((resolve) => {
                    resolve(reportData["report.json"]);
                }),
            getProcessInfo: ({ processSeqId }) =>
                new Promise((resolve) => {
                    // Conversion between schemas if /api/report and /api/process_info
                    const processInfo =
                        reportData["report.json"].processes[processSeqId];
                    const ppid =
                        processInfo["parent_seqid"] ??
                        processInfo[processInfo["parent_seqid"]].pid;
                    resolve({
                        logs: {},
                        process: {
                            ...processInfo,
                            evtid_from: 0,
                            evtid_to: 0,
                            pid: 5944,
                            ppid: ppid,
                            name: processInfo["procname"],
                            ts_from: processInfo["started_at"],
                            ts_to: processInfo["exited_at"],
                        },
                    });
                }),
            getAnalysisProcessTree: () =>
                new Promise((resolve) => {
                    resolve(reportData["process_tree.json"]);
                }),
            getScreenshotURL: (analysis_id, screenshot_idx) =>
                reportData["screenshots"] && reportData["screenshots"][screenshot_idx],
            isOffline: true,
        }),
        [reportData],
    );
    return (
        <AnalysisReportContext.Provider value={contextValue}>
            {children}
        </AnalysisReportContext.Provider>
    );
}
