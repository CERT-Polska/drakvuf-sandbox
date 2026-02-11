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

const REPORT_DATA = {
    analysisInfo: {
        dumps_metadata: [
            {
                base_address: "0x8b50000",
                filename: "dumps/8b50000_3f66521a203734af",
            },
        ],
        file: {
            name: "99b1dc4e.js",
            sha256: "5626e2a59f161cbd625b82154d7ffa212a242143ee53ec0102e6d54cdca70824",
            type: "JavaScript source, ASCII text, with very long lines (43667), with no line terminators",
        },
        id: "6aaedd3a-bfb8-45dc-9bc2-a744e27976d7",
        options: {
            job_timeout_leeway: 600,
            net_enable: true,
            no_post_restore: false,
            no_screenshotter: false,
            plugins: [
                "apimon",
                "filetracer",
                "memdump",
                "procmon",
                "socketmon",
                "tlsmon",
            ],
            sample_path:
                "/var/lib/drakrun/uploads/6aaedd3a-bfb8-45dc-9bc2-a744e27976d7.sample",
            start_command: "wscript.exe C:\\Users\\User\\Desktop\\99b1dc4e.js",
            target_filename: "99b1dc4e.js",
            target_filepath: "%USERPROFILE%\\Desktop\\99b1dc4e.js",
            timeout: 300,
        },
        screenshots: 2,
        status: "finished",
        substatus: "done",
        time_execution_started: "2026-02-11T12:33:45.389539+00:00",
        time_finished: "2026-02-11T12:39:01.930591+00:00",
        time_started: "2026-02-11T12:33:29.193338+00:00",
        vm_id: 5,
    },
    analysisSummary: {
        info: {
            time_started: "2026-02-11T12:33:29.193338+00:00",
            options: {
                target_filename: "99b1dc4e.js",
                target_filepath: "%USERPROFILE%\\Desktop",
                plugins: [
                    "apimon",
                    "filetracer",
                    "memdump",
                    "procmon",
                    "socketmon",
                    "tlsmon",
                ],
                timeout: 300,
                job_timeout_leeway: 600,
                net_enable: true,
                no_post_restore: false,
                no_screenshotter: false,
            },
            file: {
                name: "99b1dc4e.js",
                type: "JavaScript source, ASCII text, with very long lines (43667), with no line terminators",
                sha256: "5626e2a59f161cbd625b82154d7ffa212a242143ee53ec0102e6d54cdca70824",
            },
            vm_id: 5,
        },
        startup: {
            status: "Success",
            process_name: "wscript.exe",
            arguments: "C:\\Users\\User\\Desktop\\99b1dc4e.js",
            pid: 5512,
            process: 92,
        },
    },
    processTree: [],
};

function EmbeddedReport() {
    return (
        <div className="container-fluid px-4">
            <h1 className="m-4 h4">Analysis report</h1>
            <OfflineAnalysisReportProvider reportData={REPORT_DATA}>
                <AnalysisReport />
            </OfflineAnalysisReportProvider>
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
