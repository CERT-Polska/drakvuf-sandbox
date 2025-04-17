import axios from "axios";

if(import.meta.env.VITE_API_SERVER) {
    axios.defaults.baseURL = import.meta.env.VITE_API_SERVER;
}

export function getAnalysisList() {
    return axios.get("/list");
}
