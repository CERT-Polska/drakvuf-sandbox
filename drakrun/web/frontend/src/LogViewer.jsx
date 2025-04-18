import { getLog } from "./api.js";
import { useCallback, useEffect, useRef, useState } from "react";
import { LazyLog } from "@melloware/react-logviewer";

const DEFAULT_CHUNK_SIZE = 300 * 1024;

async function* getLogLoader({
    analysisId,
    logType,
    chunkSize = DEFAULT_CHUNK_SIZE,
}) {
    let currentStart = 0;
    while (1) {
        const data = await getLog({
            analysisId,
            logType,
            rangeStart: currentStart,
            rangeEnd: currentStart + (chunkSize - 1),
        });
        const dataLength = data.lastIndexOf("\n") + 1;
        yield data.slice(0, dataLength);
        currentStart += dataLength;
        if (data.length < DEFAULT_CHUNK_SIZE) {
            break;
        }
    }
}

export function LogViewer({
    analysisId,
    logType,
    className = "",
    onLineClick = () => {},
}) {
    const [loading, setLoading] = useState(true);
    const [content, setContent] = useState("");
    const logLoader = useRef(null);
    const logViewer = useRef(null);
    const loadNext = useCallback(() => {
        if (logLoader.current) {
            setLoading(true);
            logLoader.current.next().then(({ done, value }) => {
                if (done) {
                    // Generation is done, close the loader
                    logLoader.current = null;
                } else {
                    setContent((content) => content + value);
                    setLoading(false);
                }
            });
        }
    }, [analysisId, logType]);

    useEffect(() => {
        setContent("");
        setLoading(false);
        logLoader.current = getLogLoader({ analysisId, logType });
        loadNext();
    }, [analysisId, logType]);

    return (
        <div style={{ height: "600px" }} className={className}>
            <LazyLog
                ref={logViewer}
                loading={loading}
                text={content}
                onScroll={async ({ scrollHeight, scrollTop, clientHeight }) => {
                    if (
                        scrollHeight - scrollTop < clientHeight + 16 &&
                        logLoader.current &&
                        !loading
                    ) {
                        loadNext();
                    }
                }}
                onLineContentClick={(event) => {
                    onLineClick(event.target?.firstChild?.data);
                }}
                enableSearch
                wrapLines
            />
        </div>
    );
}
