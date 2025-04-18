import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faPlusCircle, faMinusCircle } from "@fortawesome/free-solid-svg-icons";

function trimProcessName(procname) {
    return procname.split("\\").at(-1);
}

export function ProcessNode({ node }) {
    let nodeStyle = "";
    if (!node.ts_from) {
        nodeStyle = "text-muted";
    } else if (!node.ts_to) {
        nodeStyle = "text-primary";
    }
    return <span className={nodeStyle}>{trimProcessName(node.procname)}</span>;
}

export function ProcessTree({ processTree, uncollapsedSeqid, setCollapse }) {
    return (
        <ul style={{ "list-style-type": "none" }}>
            {processTree.map((element) => {
                const leaf = element.children.length === 0;
                const collapsed = !uncollapsedSeqid.has(element.seqid);
                return (
                    <>
                        <li>
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
                            <ProcessNode node={element} />
                            <span className="ms-1">({element.pid})</span>
                        </li>
                        {!leaf && !collapsed ? (
                            <ProcessTree
                                processTree={element.children}
                                uncollapsedSeqid={uncollapsedSeqid}
                                setCollapse={setCollapse}
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
