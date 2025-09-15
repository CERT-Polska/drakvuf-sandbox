import axios from "axios";

if (import.meta.env.VITE_API_SERVER) {
    axios.defaults.baseURL = import.meta.env.VITE_API_SERVER;
} else {
    axios.defaults.baseURL = "/api";
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

export async function getAnalysisSummary({
    analysisId,
    abortController = undefined,
}) {
    const reportRequest = await axios.get(
        `/report/${analysisId}`,
        abortController
            ? {
                  signal: abortController.signal,
              }
            : {},
    );
    return reportRequest.data;
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

export async function getLogList({ analysisId }) {
    const logRequest = await axios.get(`/logs/${analysisId}`);
    return logRequest.data;
}

export async function getProcessInfo({ analysisId, processSeqId }) {
    const logRequest = await axios.get(
        `/process_info/${analysisId}/${processSeqId}`,
    );
    return logRequest.data;
}

export async function getProcessLog({
    analysisId,
    logType,
    selectedProcess,
    rangeStart,
    rangeEnd,
    methodsFilter = [],
}) {
    const logRequest = await axios.get(
        `/logs/${analysisId}/${logType}/process/${selectedProcess}`,
        {
            responseType: "text",
            headers: {
                Range: `bytes=${rangeStart}-${rangeEnd}`,
            },
            params: {
                filter: methodsFilter,
            },
        },
    );
    return logRequest.data;
}

export async function uploadSample({
    file,
    timeout,
    file_name,
    file_path,
    plugins,
    start_command,
    no_internet,
    no_screenshots,
    extract_archive,
    archive_password,
}) {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("timeout", timeout);
    formData.append("plugins", JSON.stringify(plugins));
    if (file_name) formData.append("file_name", file_name);
    if (file_path) formData.append("file_path", file_path);
    if (start_command) formData.append("start_command", start_command);
    if (no_internet) formData.append("no_internet", "1");
    if (no_screenshots) formData.append("no_screenshots", "1");
    if (extract_archive) formData.append("extract_archive", "1");
    if (archive_password) formData.append("archive_password", archive_password);
    const request = await axios.post("/upload", formData, {
        headers: {
            "Content-Type": "multipart/form-data",
        },
    });
    return request.data;
}
