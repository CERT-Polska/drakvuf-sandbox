import axios from "axios";

// Set REACT_APP_API_SERVER env to override default API server URL
axios.defaults.baseURL = process.env.REACT_APP_API_SERVER;

export default {
  async getList() {
    return axios.get("/list");
  },
  async getRedisState() {
    return axios.get("/redis_state");
  },
  async getLog(analysis, type) {
    return axios.get(`/logs/${analysis}/${type}`);
  },
  async getLogRange(analysis, type, from, to) {
    return axios.get(`/logs/${analysis}/${type}`, {
      responseType: "text",
      headers: {
        Range: `bytes=${from}-${to || ""}`,
      },
    });
  },
  async logIndex(analysis, type) {
    return axios.get(`/logindex/${analysis}/${type}`);
  },
  async listLogs(analysis) {
    return axios.get(`/logs/${analysis}`);
  },
  async getMetadata(analysis) {
    return axios.get(`/metadata/${analysis}`);
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
      if (option === "plugins")
        formData.append(option, JSON.stringify(options[option]));
      else formData.append(option, options[option]);
    }
    return axios.post("/upload", formData, {
      headers: {
        "Content-Type": "multipart/form-data",
      },
    });
  },
};
