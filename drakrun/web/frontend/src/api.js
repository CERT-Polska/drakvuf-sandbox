import axios from "axios";

if (import.meta.env.VITE_API_SERVER) {
    axios.defaults.baseURL = import.meta.env.VITE_API_SERVER;
}

export async function getAnalysisList({ abortController }) {
    const listRequest = await axios.get("/list", {
        signal: abortController.signal,
    });
    return listRequest.data;
}

export async function getAnalysisStatus({
    analysisId,
    abortController = undefined,
}) {
    const listRequest = await axios.get(
        `/status/${analysisId}`,
        abortController
            ? {
                  signal: abortController.signal,
              }
            : {},
    );
    return listRequest.data;
}

export async function getAnalysisProcessTree({
    analysisId,
    abortController = undefined,
}) {
    const listRequest = await axios.get(
        `/processed/${analysisId}/process_tree`,
        abortController
            ? {
                  signal: abortController.signal,
              }
            : {},
    );
    return listRequest.data;
}

export async function getLog({ analysisId, logType, rangeStart, rangeEnd }) {
    const logRequest = await axios.get(`/logs/${analysisId}/${logType}`, {
        responseType: "text",
        headers: {
            Range: `bytes=${rangeStart}-${rangeEnd}`,
        },
    });
    return logRequest.data;
}
