import { useParams } from "react-router-dom";
import { useCallback, useEffect, useRef, useState } from "react";
import { getAnalysisStatus } from "./api.js";
import { CanceledError } from "axios";
import { isStatusPending } from "./analysisStatus.js";
import {
    AnalysisPendingView,
    AnalysisPendingStatusBox,
} from "./AnalysisPendingView.jsx";
import { AnalysisReport } from "./AnalysisReport.jsx";
import { OnlineAnalysisReportProvider } from "./AnalysisReportContext.jsx";

function AnalysisViewComponent({ analysisId }) {
    const checkInterval = useRef(null);
    const [analysisInfo, setAnalysisInfo] = useState();
    const [error, setError] = useState();

    const checkStatus = useCallback(() => {
        getAnalysisStatus({ analysisId })
            .then((response) => {
                if (response && response["time_execution_started"]) {
                    // Inject remaining time here. We're calling this method every second,
                    // while tracking a pending analysis status, so it's very good place
                    // for injecting such information
                    const timeout = response.options?.timeout;
                    const elapsedSeconds =
                        (new Date() -
                            new Date(response["time_execution_started"])) /
                        1000;
                    response["remaining_time"] = Math.max(
                        0,
                        timeout - elapsedSeconds,
                    );
                }
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
    return (
        <OnlineAnalysisReportProvider analysisInfo={analysisInfo}>
            <AnalysisReport />
        </OnlineAnalysisReportProvider>
    );
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
