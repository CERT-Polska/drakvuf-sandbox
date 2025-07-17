import { useEffect, useState } from "react";
import { getAnalysisProcessTree } from "./api.js";
import { ProcessTree } from "./ProcessTree.jsx";

function isProcessInteresting(process) {
    return process.procname.endsWith("explorer.exe");
}

function getProcessParents(processTree, processId) {
    let stack = processTree.map((element) => ({ parents: [], element }));
    while (stack.length > 0) {
        let { parents, element } = stack.shift();
        if (element.seqid === processId) {
            return parents;
        }
        if (element.children && element.children.length > 0) {
            stack = [
                ...element.children.map((child) => ({
                    parents: [...parents, element.seqid],
                    element: child,
                })),
                ...stack,
            ];
        }
    }
    return undefined;
}

function getInterestingProcesses(processTree) {
    let activeSet = new Set();
    for (let process of processTree) {
        if (isProcessInteresting(process)) {
            activeSet.add(process.seqid);
        }
        if (process.children.length > 0) {
            const activeChildren = getInterestingProcesses(process.children);
            if (activeChildren.size) {
                activeSet = activeSet.union(activeChildren);
                activeSet.add(process.seqid);
            }
        }
    }
    return activeSet;
}

export function ProcessTreeView({
    analysisId,
    selectedProcess,
    onProcessSelect,
}) {
    const [uncollapsed, setUncollapsed] = useState(new Set());
    const [processTree, setProcessTree] = useState();
    const [error, setError] = useState();

    useEffect(() => {
        getAnalysisProcessTree({ analysisId })
            .then((data) => {
                setProcessTree(data);
                setUncollapsed(getInterestingProcesses(data));
            })
            .catch((e) => {
                console.error(e);
                setError(e);
            });
    }, []);

    useEffect(() => {
        if (!processTree) return;
        const parents = getProcessParents(processTree, selectedProcess);
        if (parents) {
            setUncollapsed((currentValue) =>
                currentValue.union(new Set(parents)),
            );
        }
    }, [selectedProcess, processTree]);

    return (
        <div className="card">
            <div className="card-body">
                {typeof processTree === "undefined" ? (
                    <span>Loading process tree...</span>
                ) : (
                    []
                )}
                {typeof error !== "undefined" ? (
                    <span className="text-danger">
                        Unable to load process tree
                    </span>
                ) : (
                    []
                )}
                {typeof processTree !== "undefined" ? (
                    <ProcessTree
                        processTree={processTree}
                        uncollapsedSeqid={uncollapsed}
                        setCollapse={(seqid) => {
                            const collapse = uncollapsed.has(seqid);
                            setUncollapsed((currentValue) => {
                                let newSet = new Set(currentValue);
                                if (!collapse) {
                                    newSet.add(seqid);
                                } else {
                                    newSet.delete(seqid);
                                }
                                return newSet;
                            });
                        }}
                        selected={selectedProcess}
                        onSelect={(seqid) => {
                            onProcessSelect(seqid);
                        }}
                    />
                ) : (
                    []
                )}
            </div>
        </div>
    );
}
