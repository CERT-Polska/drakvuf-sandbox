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

export async function getAnalysisStatus({ analysisId, abortController }) {
    const listRequest = await axios.get(`/status/${analysisId}`, {
        signal: abortController.signal,
    });
    return listRequest.data;
}
