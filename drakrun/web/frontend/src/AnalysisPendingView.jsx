import { AnalysisLiveInteraction } from "./AnalysisLiveInteraction.jsx";
import { AnalysisStatusBadge } from "./AnalysisStatusBadge.jsx";
import { AnalysisMetadataTable } from "./AnalysisMetadataTable.jsx";
import { useState } from "react";
import { Tab, TabSwitcher } from "./TabSwitcher.jsx";

export function AnalysisPendingStatusBox({ children }) {
    return (
        <div className="card">
            <div className="card-body">
                <div className="pb-2">{children}</div>
                <div className="progress">
                    <div
                        className="progress-bar progress-bar-striped progress-bar-animated"
                        role="progressbar"
                        aria-valuenow="100"
                        aria-valuemin="0"
                        aria-valuemax="100"
                        style={{ width: "100%" }}
                    ></div>
                </div>
            </div>
        </div>
    );
}

function AnalysisPendingTabs({ analysis }) {
    const [activeTab, setActiveTab] = useState("metadata");
    const enableLiveInteraction = (
        analysis["vm_id"] && analysis["status"] === "started" && analysis["substatus"] !== "starting_vm"
    )
    return (
        <TabSwitcher
            getHeader={(tabid) => {
                if (tabid === "metadata") {
                    return "Analysis info";
                } else if (tabid === "live-interaction") {
                    return `Live interaction (vm-${analysis["vm_id"]})`;
                }
            }}
            activeTab={activeTab}
            onTabSwitch={setActiveTab}
        >
            <Tab tab="metadata">
                <AnalysisMetadataTable analysis={analysis} />
            </Tab>
            {enableLiveInteraction ? (
                <Tab tab="live-interaction">
                    <AnalysisLiveInteraction vmId={analysis["vm_id"]} />
                </Tab>
            ) : (
                []
            )}
        </TabSwitcher>
    );
}

export function AnalysisPendingView({ analysis }) {
    return (
        <>
            <div className="row">
                <div className="col">
                    <AnalysisPendingStatusBox>
                        <div>Please wait until analysis is completed...</div>
                        <div>
                            <div className="me-2 py-2 d-inline-block">
                                Current status:
                            </div>
                            <AnalysisStatusBadge
                                status={analysis.status}
                                substatus={analysis.substatus}
                            />
                        </div>
                    </AnalysisPendingStatusBox>
                </div>
            </div>
            <div className="row py-4">
                <div className="col">
                    <div className="card">
                        <div className="card-body">
                            <AnalysisPendingTabs analysis={analysis} />
                        </div>
                    </div>
                </div>
            </div>
        </>
    );
}
