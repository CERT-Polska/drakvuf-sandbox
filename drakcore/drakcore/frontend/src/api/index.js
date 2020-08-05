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
  async getSha256(analysis) {
    return axios.get(`/sha256/${analysis}`);
  },
  async getStatus(analysis) {
    return axios.get(`/status/${analysis}`);
  },
  async getGraph(analysis) {
    return axios.get(`/graph/${analysis}`);
  },
  async getProcessTree(analysis) {
    return axios.get(`/processed/${analysis}/process_tree`);
  },
  async getApiCalls(analysis, pid) {
    return axios.get(`/processed/${analysis}/apicall/${pid}`);
  },
  async query(q) {
    return axios.get("/query", { params: { q: q } });
  },
  async uploadSample(file, options) {
    let formData = new FormData();
    formData.append("file", file);
    for (const option in options) {
      formData.append(option, options[option]);
    }
    return axios.post("/upload", formData, {
      headers: {
        "Content-Type": "multipart/form-data",
      },
    });
  },
};
