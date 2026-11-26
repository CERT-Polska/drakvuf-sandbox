import React, { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import "bootstrap";
import "bootstrap/dist/css/bootstrap.css";
import "./App.css";
import "./layout.css";

import { HashRouter } from "react-router-dom";
import { AppHeader, AppFooter } from "./App";
import { OfflineAnalysisReportProvider } from "./AnalysisReportContext.jsx";
import { AnalysisReport } from "./AnalysisReport.jsx";
import { ErrorBoundary } from "./ErrorBoundary.jsx";
import { NotificationsProvider } from "./NotificationsProvider.jsx";

async function loadOfflineFiles() {
    const encoded = window.OFFLINE_FILES_GZIP_BASE64;
    if (!encoded) {
        return null;
    }
    const compressed = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
    const stream = new Blob([compressed])
        .stream()
        .pipeThrough(new DecompressionStream("gzip"));
    return JSON.parse(await new Response(stream).text());
}

function EmbeddedReport({ reportData, loadError }) {
    let content;
    if (loadError) {
        content = (
            <div className="text-danger">
                Failed to load the analysis data embedded in the file:{" "}
                {String(loadError)}
            </div>
        );
    } else if (reportData) {
        content = (
            <OfflineAnalysisReportProvider reportData={reportData}>
                <AnalysisReport />
            </OfflineAnalysisReportProvider>
        );
    } else {
        content = "There are no analysis data embedded in the file";
    }
    return (
        <div className="container-fluid px-4">
            <h1 className="m-4 h4">Analysis report</h1>
            {content}
        </div>
    );
}

function EmbeddedReportApp({ reportData, loadError }) {
    return (
        <>
            <AppHeader />
            <div id="layoutSidenav">
                <div id="layoutSidenav_content">
                    <main>
                        <ErrorBoundary>
                            <EmbeddedReport
                                reportData={reportData}
                                loadError={loadError}
                            />
                        </ErrorBoundary>
                    </main>
                    <AppFooter />
                </div>
            </div>
        </>
    );
}

function render({ reportData = null, loadError = null }) {
    createRoot(document.getElementById("root")).render(
        <StrictMode>
            <HashRouter>
                <NotificationsProvider>
                    <EmbeddedReportApp
                        reportData={reportData}
                        loadError={loadError}
                    />
                </NotificationsProvider>
            </HashRouter>
        </StrictMode>,
    );
}

loadOfflineFiles().then(
    (reportData) => render({ reportData }),
    (err) => {
        console.error(err);
        render({ loadError: err });
    },
);
