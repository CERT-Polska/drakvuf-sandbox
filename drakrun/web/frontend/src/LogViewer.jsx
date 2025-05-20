import { getLog } from "./api.js";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { LazyLog } from "@melloware/react-logviewer";

const DEFAULT_CHUNK_SIZE = 300 * 1024;

async function* getLogLoader({
    analysisId,
    logType,
    chunkSize = DEFAULT_CHUNK_SIZE,
}) {
    let currentStart = 0;
    while (1) {
        try {
            const data = await getLog({
                analysisId,
                logType,
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

export function LogViewer({
    analysisId,
    logType,
    className = "",
    onLineClick = () => {},
}) {
    const [loading, setLoading] = useState(true);
    const [content, setContent] = useState("");
    const logLoader = useMemo(
        () => getLogLoader({ analysisId, logType }),
        [analysisId, logType],
    );
    const logViewer = useRef(null);
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
        setContent("");
        setLoading(false);
        loadNext();
    }, [logLoader]);

    return (
        <div style={{ height: "600px" }} className={className}>
            <LazyLog
                ref={logViewer}
                loading={loading}
                text={content}
                onScroll={({ scrollHeight, scrollTop, clientHeight }) => {
                    if (
                        scrollHeight - scrollTop < clientHeight + 16 &&
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
