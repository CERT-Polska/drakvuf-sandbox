import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { LazyLog } from "@melloware/react-logviewer";

const DEFAULT_CHUNK_SIZE = 300 * 1024;

export async function* getLogLoader({
    getLogEntries,
    chunkSize = DEFAULT_CHUNK_SIZE,
}) {
    let currentStart = 0;
    while (1) {
        try {
            const data = await getLogEntries({
                rangeStart: currentStart,
                rangeEnd: currentStart + (chunkSize - 1),
            });
            const dataLength = data.lastIndexOf("\n") + 1;
            yield data.slice(0, dataLength);
            currentStart += dataLength;
        } catch (err) {
            if (err.status === 416) {
                break;
            } else {
                throw err;
            }
        }
    }
}

export function LogViewer({ logLoaderFactory }) {
    const [loading, setLoading] = useState(true);
    const [content, setContent] = useState("");
    const logLoader = useMemo(() => logLoaderFactory(), [logLoaderFactory]);
    const logViewer = useRef(null);
    const [jsonInspectedLine, setJsonInspectedLine] = useState(null);

    const inspectLine = useCallback((line) => {
        try {
            const data = JSON.parse(line.trimEnd());
            setJsonInspectedLine(JSON.stringify(data, null, 4));
        } catch (err) {
            setJsonInspectedLine(null);
        }
    }, []);

    const loadNext = useCallback(() => {
        setLoading(true);
        logLoader.next().then(({ done, value }) => {
            if (!done) {
                setContent((content) => content + value);
            }
            setLoading(false);
        });
    }, [logLoader]);

    useEffect(() => {
        console.log("new log loader");
        setContent(" ");
        setLoading(false);
        loadNext();
    }, [logLoader]);

    return (
        <>
            <div style={{ height: "600px" }} className="flex-grow-1">
                <LazyLog
                    ref={logViewer}
                    loading={loading}
                    text={content}
                    onScroll={async ({
                        scrollHeight,
                        scrollTop,
                        clientHeight,
                    }) => {
                        if (
                            scrollHeight - scrollTop < clientHeight + 16 &&
                            !loading
                        ) {
                            loadNext();
                        }
                    }}
                    onLineContentClick={(event) => {
                        inspectLine(event.target?.firstChild?.data);
                    }}
                    enableSearch
                    wrapLines
                />
            </div>
            <div>
                {jsonInspectedLine ? (
                    <div>
                        <div
                            className="fw-bold"
                            style={{ borderTop: "black 1px solid" }}
                        >
                            JSON inspector
                        </div>
                        <pre>{jsonInspectedLine}</pre>
                    </div>
                ) : (
                    []
                )}
            </div>
        </>
    );
}
