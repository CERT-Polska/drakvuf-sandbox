import axios from "axios";

// uncomment this line to use different API server
// axios.defaults.baseURL = '';

export default {
    async getList() {
        return axios.get("/list");
    },
    async getLog(analysis, type) {
        return axios.get(`/logs/${analysis}/${type}`);
    },
    async listLogs(analysis) {
        return axios.get(`/logs/${analysis}`);
    },
    async getStatus(analysis) {
        return axios.get(`/status/${analysis}`);
    },
    async getGraph(analysis) {
        return axios.get(`/graph/${analysis}`);
    },
    async getProcessTree(analysis) {
        return axios.get(`/processed/${analysis}/process_tree.json`);
    },
    async query(q) {
        return axios.get("/query", { params: { q: q } });
    }
};
