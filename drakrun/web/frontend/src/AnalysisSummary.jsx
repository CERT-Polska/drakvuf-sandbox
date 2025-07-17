import { createContext, useCallback, useContext, useState } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faMinus, faPlus } from "@fortawesome/free-solid-svg-icons";
import { ProcessBadge } from "./ProcessBadge.jsx";

const COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3389: "RDP",
    5985: "WinRM",
};

function formatIP(host, port, protocol) {
    if (protocol.endsWith("v6")) {
        return `[${host}]:${port}`;
    } else {
        return `${host}:${port}`;
    }
}

const AnalysisSummaryContext = createContext({});

export function useAnalysisSummary() {
    return useContext(AnalysisSummaryContext).summary;
}

function SummarySection({ header, badgeType, badgeValue, children }) {
    const [collapsed, setCollapsed] = useState(false);
    return (
        <div className="my-3 p-3 bg-white border rounded box-shadow">
            <h5
                className="border-bottom border-gray pb-2 mb-2"
                style={{ cursor: "pointer" }}
                onClick={() => setCollapsed((collapsed) => !collapsed)}
            >
                <FontAwesomeIcon
                    icon={collapsed ? faPlus : faMinus}
                    className="me-2"
                />
                {header}
                {badgeType ? (
                    <span className={`badge rounded-pill bg-${badgeType} ms-2`}>
                        {badgeValue}
                    </span>
                ) : (
                    []
                )}
            </h5>
            <div>{!collapsed ? children : []}</div>
        </div>
    );
}

function SummaryProcessBadge({ processId }) {
    const { summary: analysisSummary, selectProcess } = useContext(
        AnalysisSummaryContext,
    );
    const process = analysisSummary?.processes[processId];
    if (!process) {
        return [];
    }
    return (
        <ProcessBadge
            process={process}
            onClick={() => selectProcess(processId)}
        />
    );
}

function SummaryStartupSection() {
    const analysisSummary = useAnalysisSummary();
    const startupInfo = analysisSummary["startup"];
    const startupStatus = startupInfo["status"];

    if (startupStatus === "Success") {
        let processInfo = null;
        let badgeValue = "Success";
        let badgeType = "success";
        if (startupInfo.process && analysisSummary.processes) {
            processInfo = analysisSummary.processes[startupInfo.process];
        }
        if (processInfo?.exit_code & 0xc0000000) {
            badgeValue = "Exited with error";
            badgeType = "warning";
        }
        return (
            <SummarySection
                header="Process creation"
                badgeValue={badgeValue}
                badgeType={badgeType}
            >
                <table
                    className="table table-borderless"
                    style={{ width: "auto" }}
                >
                    <tbody>
                        <tr>
                            <th>Process name:</th>
                            <td>
                                {startupInfo["process_name"]}
                                {processInfo ? (
                                    <SummaryProcessBadge
                                        processId={startupInfo["process"]}
                                    />
                                ) : (
                                    []
                                )}
                            </td>
                        </tr>
                        <tr>
                            <th>Arguments:</th>
                            <td>
                                {startupInfo["arguments"] || (
                                    <span className="text-muted">(empty)</span>
                                )}
                            </td>
                        </tr>
                        {processInfo?.exited_at ? (
                            <>
                                <tr>
                                    <th>Exited at:</th>
                                    <td>{processInfo["exited_at"]}</td>
                                </tr>
                                <tr>
                                    <th>Exit code:</th>
                                    <td>
                                        {processInfo["exit_code_str"]} (0x
                                        {processInfo["exit_code"].toString(16)})
                                    </td>
                                </tr>
                                <tr>
                                    <th>Terminated by:</th>
                                    <td>
                                        {processInfo["killed_by"] ? (
                                            <SummaryProcessBadge
                                                processId={
                                                    processInfo["killed_by"]
                                                }
                                            />
                                        ) : (
                                            <span>(self)</span>
                                        )}
                                    </td>
                                </tr>
                            </>
                        ) : (
                            []
                        )}
                    </tbody>
                </table>
            </SummarySection>
        );
    } else {
        return (
            <SummarySection
                header="Process creation"
                badgeValue={startupStatus}
                badgeType="danger"
            >
                <table
                    className="table table-borderless"
                    style={{ width: "auto" }}
                >
                    <tbody>
                        <tr>
                            <th>Error:</th>
                            <td>
                                {startupInfo["error"]} (0x
                                {startupInfo["error_code"].toString(16)})
                            </td>
                        </tr>
                    </tbody>
                </table>
            </SummarySection>
        );
    }
}

function TTPRow({ ttp }) {
    return (
        <li>
            <div>
                <b>{ttp.name}</b>
            </div>
            <div>
                {ttp.process_seqids.map((p) => (
                    <SummaryProcessBadge processId={p} />
                ))}
            </div>
        </li>
    );
}

function SummaryTTPsSection() {
    const analysisSummary = useAnalysisSummary();
    const ttpsInfo = analysisSummary["ttps"];
    if (!ttpsInfo) return [];
    return (
        <SummarySection
            header="TTPs"
            badgeType="primary"
            badgeValue={ttpsInfo.length}
        >
            <ul>
                {ttpsInfo.map((ttp, idx) => (
                    <TTPRow ttp={ttp} key={`ttp${idx}`} />
                ))}
            </ul>
        </SummarySection>
    );
}

function HTTPRow({ httpRequest }) {
    return (
        <li className="mb-2 p-2 border-bottom">
            <div>
                <span className="text-nowrap font-monospace">
                    {httpRequest.verb ? (
                        <span className="badge rounded-pill bg-primary me-2">
                            {httpRequest.verb}
                        </span>
                    ) : (
                        <span className="badge rounded-pill bg-secondary me-2">
                            unknown
                        </span>
                    )}
                    {httpRequest.path}
                </span>
                {httpRequest["server_name"] ? (
                    <div>
                        <b>Host: </b>
                        <span className="text-nowrap font-monospace">
                            {httpRequest["server_name"] +
                                (httpRequest["server_port"]
                                    ? ":" + httpRequest["server_port"]
                                    : "")}
                        </span>
                    </div>
                ) : (
                    []
                )}
                {httpRequest["user_agent"] ? (
                    <div>
                        <b>User-Agent: </b>
                        <span className="text-nowrap font-monospace">
                            {httpRequest["user_agent"]}
                        </span>
                    </div>
                ) : (
                    []
                )}
                {httpRequest["extra_headers"] ? (
                    <div>
                        <b>Extra headers: </b>
                        <pre>{httpRequest["extra_headers"]}</pre>
                    </div>
                ) : (
                    []
                )}
                {httpRequest["process_seqid"] ? (
                    <div>
                        <b>Process: </b>
                        <SummaryProcessBadge
                            processId={httpRequest["process_seqid"]}
                        />
                    </div>
                ) : (
                    []
                )}
            </div>
        </li>
    );
}

function SummaryHTTPSection() {
    const analysisSummary = useAnalysisSummary();
    const httpRequests = analysisSummary["http_requests"];
    if (!httpRequests) return [];
    return (
        <SummarySection
            header="HTTP requests"
            badgeType="primary"
            badgeValue={httpRequests.length}
        >
            <ul style={{ overflow: "auto" }}>
                {httpRequests.map((httpReq, idx) => (
                    <HTTPRow httpRequest={httpReq} key={`httpreq-${idx}`} />
                ))}
            </ul>
        </SummarySection>
    );
}

function SummaryCrackedURLs() {
    const analysisSummary = useAnalysisSummary();
    const crackedURLs = analysisSummary["cracked_urls"];
    if (!crackedURLs) return [];
    return (
        <SummarySection
            header="Cracked URLs"
            badgeType="primary"
            badgeValue={crackedURLs.length}
        >
            <ul style={{ overflow: "auto" }}>
                {crackedURLs.map((urlinfo, idx) => (
                    <li key={`url-${idx}`}>
                        <span className="text-nowrap font-monospace">
                            {urlinfo.url}
                        </span>
                        <span>
                            {urlinfo.process_seqids.map((p) => (
                                <SummaryProcessBadge processId={p} />
                            ))}
                        </span>
                    </li>
                ))}
            </ul>
        </SummarySection>
    );
}

function SummaryModifiedFilesSection() {
    const analysisSummary = useAnalysisSummary();
    const modifiedFiles = analysisSummary["modified_files"];
    if (!modifiedFiles) return [];
    return (
        <SummarySection
            header="Modified files"
            badgeType="primary"
            badgeValue={modifiedFiles.length}
        >
            <ul style={{ overflow: "auto" }}>
                {modifiedFiles.map((mfile, idx) => (
                    <li key={`mfile-${idx}`}>
                        <span className="text-nowrap font-monospace">
                            {mfile.filename}
                        </span>
                        <span>
                            {mfile.process_seqids.map((p) => (
                                <SummaryProcessBadge processId={p} />
                            ))}
                        </span>
                    </li>
                ))}
            </ul>
        </SummarySection>
    );
}

function SummaryDeletedFilesSection() {
    const analysisSummary = useAnalysisSummary();
    const deletedFiles = analysisSummary["deleted_files"];
    if (!deletedFiles) return [];
    return (
        <SummarySection
            header="Deleted files"
            badgeType="primary"
            badgeValue={deletedFiles.length}
        >
            <ul style={{ overflow: "auto" }}>
                {deletedFiles.map((mfile, idx) => (
                    <li key={`mfile-${idx}`}>
                        <span className="text-nowrap font-monospace">
                            {mfile.filename}
                        </span>
                        <span>
                            {mfile.process_seqids.map((p) => (
                                <SummaryProcessBadge processId={p} />
                            ))}
                        </span>
                    </li>
                ))}
            </ul>
        </SummarySection>
    );
}

function ConnectionPortBadge({ port }) {
    if (!COMMON_PORTS[port]) return [];
    return (
        <span className="badge rounded-pill bg-secondary me-2">
            {COMMON_PORTS[port]}
        </span>
    );
}

function ConnectionRow({ connection }) {
    return (
        <li className="mb-2 p-2 border-bottom">
            <div>
                <span className="badge rounded-pill bg-primary me-2">
                    {connection.protocol}
                </span>
                <ConnectionPortBadge port={connection.remote_port} />
                {formatIP(
                    connection.remote_ip,
                    connection.remote_port,
                    connection.protocol,
                )}
                {connection.process_seqids.map((p) => (
                    <SummaryProcessBadge processId={p} />
                ))}
            </div>
        </li>
    );
}

function SummaryConnectionsSection() {
    const analysisSummary = useAnalysisSummary();
    const connections = analysisSummary["connections"];
    if (!connections) return [];
    return (
        <SummarySection
            header="Connections"
            badgeType="primary"
            badgeValue={connections.length}
        >
            <ul style={{ overflow: "auto" }}>
                {connections.map((conn, idx) => (
                    <ConnectionRow connection={conn} key={`conn-${idx}`} />
                ))}
            </ul>
        </SummarySection>
    );
}

function SummaryDNSSection() {
    const analysisSummary = useAnalysisSummary();
    const dnsQueries = analysisSummary["dns_queries"];
    if (!dnsQueries) return [];
    return (
        <SummarySection
            header="Domain queries"
            badgeType="primary"
            badgeValue={dnsQueries.length}
        >
            <ul style={{ overflow: "auto" }}>
                {dnsQueries.map((dnsq, idx) => (
                    <li key={`dns-${idx}`}>
                        <span className="text-nowrap font-monospace">
                            {dnsq["domain"]}
                        </span>
                        <span>
                            {dnsq.process_seqids.map((p) => (
                                <SummaryProcessBadge processId={p} />
                            ))}
                        </span>
                    </li>
                ))}
            </ul>
        </SummarySection>
    );
}

export function AnalysisSummary({ analysisSummary, setSelectedProcess }) {
    const selectProcess = useCallback(
        (processId) => {
            setSelectedProcess(processId);
        },
        [setSelectedProcess],
    );

    if (typeof analysisSummary === "undefined") {
        return <div>Loading analysis summary report...</div>;
    }
    if (analysisSummary === null) {
        return (
            <div className="text-danger">
                Failed to load analysis summary report.
            </div>
        );
    }
    if (!Object.keys(analysisSummary).some((k) => k === "startup")) {
        return (
            <div className="text-danger">
                Failed to load analysis summary report: missing "startup" key.
            </div>
        );
    }

    return (
        <AnalysisSummaryContext.Provider
            value={{
                summary: analysisSummary,
                selectProcess,
            }}
        >
            <SummaryStartupSection />
            <SummaryDNSSection />
            <SummaryHTTPSection />
            <SummaryCrackedURLs />
            <SummaryConnectionsSection />
            <SummaryModifiedFilesSection />
            <SummaryDeletedFilesSection />
            <SummaryTTPsSection />
        </AnalysisSummaryContext.Provider>
    );
}
