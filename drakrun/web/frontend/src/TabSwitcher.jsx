import { useState } from "react";

export function TabSwitcher({
    tabIds,
    getHeader,
    renderContent,
    tabClassName = "nav-tabs",
    contentClassName = "",
}) {
    const [activeTab, setActiveTab] = useState(tabIds[0]);
    return (
        <>
            <nav>
                <div
                    className={`nav ${tabClassName}`}
                    id="nav-tab"
                    role="tablist"
                >
                    {tabIds.map((tabId) => (
                        <button
                            className={`nav-link ${activeTab === tabId ? "active" : ""}`}
                            type="button"
                            role="tab"
                            onClick={() => setActiveTab(tabId)}
                            key={`tab-${tabId}`}
                        >
                            {getHeader(tabId)}
                        </button>
                    ))}
                </div>
            </nav>
            <div
                className={`tab-content ${contentClassName}`}
                id="nav-tabContent"
            >
                <div className="tab-pane active" role="tabpanel">
                    {renderContent(activeTab)}
                </div>
            </div>
        </>
    );
}
