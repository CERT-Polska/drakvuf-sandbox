import React, { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import "bootstrap";
import "bootstrap/dist/css/bootstrap.css";
import "./App.css";
import "startbootstrap-sb-admin/dist/css/styles.css";

import { HashRouter } from "react-router-dom";
import { AppHeader, AppFooter } from "./App";
import { OfflineAnalysisReportProvider } from "./AnalysisReportContext.jsx";
import { AnalysisReport } from "./AnalysisReport.jsx";

function EmbeddedReport() {
    return (
        <div className="container-fluid px-4">
            <h1 className="m-4 h4">Analysis report</h1>
            {
                window.OFFLINE_FILES ?
                    <OfflineAnalysisReportProvider reportData={window.OFFLINE_FILES}>
                        <AnalysisReport />
                    </OfflineAnalysisReportProvider>
                    : "There are no analysis data embedded in the file"
            }
        </div>
    );
}

function EmbeddedReportApp() {
    return (
        <>
            <AppHeader />
            <div id="layoutSidenav">
                <div id="layoutSidenav_content">
                    <main>
                        <EmbeddedReport />
                    </main>
                    <AppFooter />
                </div>
            </div>
        </>
    );
}

createRoot(document.getElementById("root")).render(
    <StrictMode>
        <HashRouter>
            <EmbeddedReportApp />
        </HashRouter>
    </StrictMode>,
);
