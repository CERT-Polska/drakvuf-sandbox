import { createContext, Children } from "react";
import { useContext } from "react";

const TabContext = createContext(undefined);

export function useTabContext() {
    return useContext(TabContext);
}

export function TabSwitcher({
    activeTab,
    onTabSwitch,
    children,
    tabs = undefined,
    getHeader = (tab) => tab,
    tabClassName = "nav-tabs",
    contentClassName = "",
}) {
    return (
        <TabContext.Provider value={{ activeTab, onTabSwitch }}>
            <>
                <nav>
                    <div
                        className={`nav ${tabClassName}`}
                        id="nav-tab"
                        role="tablist"
                    >
                        {(
                            tabs ??
                            Children.map(children, (child) => child?.props?.tab)
                        ).map((tab) => {
                            return (
                                <button
                                    className={`nav-link ${activeTab === tab ? "active" : ""}`}
                                    type="button"
                                    role="tab"
                                    onClick={() => onTabSwitch(tab)}
                                    key={`tab-${tab}`}
                                >
                                    {getHeader(tab)}
                                </button>
                            );
                        })}
                    </div>
                </nav>
                <div
                    className={`tab-content ${contentClassName}`}
                    id="nav-tabContent"
                >
                    <div className="tab-pane active" role="tabpanel">
                        {children}
                    </div>
                </div>
            </>
        </TabContext.Provider>
    );
}

export function Tab({ tab, children }) {
    const tabContext = useTabContext();
    if (tabContext.activeTab === tab) {
        return children;
    } else {
        return [];
    }
}
