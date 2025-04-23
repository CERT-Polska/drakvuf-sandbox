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

export async function getLogList({ analysisId }){
    const logRequest = await axios.get(`/logs/${analysisId}`)
    return logRequest.data;
}

export async function uploadSample({file, timeout, file_name, plugins, start_command}) {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("timeout", timeout);
    formData.append("plugins", JSON.stringify(plugins))
    if(file_name)
        formData.append("file_name", file_name);
    if(start_command)
        formData.append("start_command", start_command);
    const request = await axios.post("/upload", formData, {
        headers: {
            "Content-Type": "multipart/form-data"
        }
    })
    return request.data;
}
