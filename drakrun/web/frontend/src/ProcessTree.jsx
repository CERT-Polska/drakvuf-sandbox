import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faPlusCircle, faMinusCircle } from "@fortawesome/free-solid-svg-icons";
import { useEffect, useRef} from "react";
import { Tooltip } from "bootstrap/js/index.esm.js";

function trimProcessName(procname) {
    return procname.split("\\").at(-1);
}

function TooltipSpan({className, tooltip, children}) {
    const node = useRef(undefined);
    useEffect(() => {
        if(node.current) {
            const tooltip = new Tooltip(node.current);
            return () => tooltip.dispose();
        }
    }, []);
    if(tooltip) {
        return <span ref={node} className={className} data-bs-toggle={tooltip} data-bs-placement="right"
                     data-bs-title={tooltip}>{children}</span>;
    } else {
        return <span ref={node} className={className}>{children}</span>;
    }
}

export function ProcessNode({ node, onClick }) {
    let nodeStyle = "";
    if (!node.ts_from) {
        nodeStyle = "text-muted";
    } else if (!node.ts_to) {
        nodeStyle = "text-primary";
    }
    const commandLine = (node.args || []).join(" ");
    return (
        <button className="btn btn-inline-link" onClick={onClick}>
            <TooltipSpan className={nodeStyle} tooltip={commandLine}>{trimProcessName(node.procname)}</TooltipSpan>
            <span className="ms-1">({node.pid})</span>
        </button>
    );
}

export function ProcessTree({ processTree, uncollapsedSeqid, setCollapse, selected, onSelect = () => {}}) {
    return (
        <ul style={{ "list-style-type": "none" }}>
            {processTree.map((element) => {
                const leaf = element.children.length === 0;
                const collapsed = !uncollapsedSeqid.has(element.seqid);
                const isSelected = (element.seqid === selected);
                return (
                    <>
                        <li className={isSelected ? "selected" : ""}>
                            {!leaf ? (
                                <FontAwesomeIcon
                                    icon={
                                        collapsed ? faPlusCircle : faMinusCircle
                                    }
                                    className="me-1"
                                    style={{ cursor: "pointer" }}
                                    onClick={(ev) => {
                                        ev.preventDefault();
                                        setCollapse(element.seqid);
                                    }}
                                />
                            ) : (
                                <FontAwesomeIcon
                                    icon={faPlusCircle}
                                    className="me-1"
                                    style={{ visibility: "hidden" }}
                                />
                            )}
                            <ProcessNode node={element} onClick={() => onSelect(element.seqid)}/>
                        </li>
                        {!leaf && !collapsed ? (
                            <ProcessTree
                                processTree={element.children}
                                uncollapsedSeqid={uncollapsedSeqid}
                                setCollapse={setCollapse}
                                selected={selected}
                                onSelect={onSelect}
                            />
                        ) : (
                            []
                        )}
                    </>
                );
            })}
        </ul>
    );
}
