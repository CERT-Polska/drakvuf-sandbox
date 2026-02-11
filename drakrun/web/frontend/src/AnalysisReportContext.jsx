import React, { useContext, useMemo } from "react";
import {
    getAnalysisSummary,
    getProcessInfo,
    getAnalysisProcessTree,
} from "./api.js";

const AnalysisReportContext = React.createContext({});

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
            analysisInfo: reportData.analysisInfo,
            getAnalysisSummary: () =>
                new Promise((resolve) => {
                    resolve(reportData.analysisSummary);
                }),
            getAnalysisProcessTree: () =>
                new Promise((resolve) => {
                    resolve(reportData.processTree);
                }),
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
