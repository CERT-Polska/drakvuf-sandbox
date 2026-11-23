import { isCancel } from "axios";

/**
 * Turn any thrown value (axios error, Error, string, ...) into a message
 * that can be rendered. API errors use the "error" field of the JSON body
 * returned by the backend, e.g. {"error": "Data not found"}.
 *
 * @param {*} err
 * @returns {string}
 */
export function formatApiError(err) {
    if (err === null || err === undefined) {
        return "Unknown error";
    }
    if (typeof err === "string") {
        return err;
    }
    const data = err.response?.data;
    let detail;
    if (typeof data?.error === "string") {
        detail = data.error;
    } else if (typeof data === "string" && data.trim()) {
        detail = data.trim();
    }
    if (detail) {
        const status = err.response?.status;
        return status ? `${detail} (HTTP ${status})` : detail;
    }
    if (typeof err.message === "string" && err.message) {
        return err.message;
    }
    return String(err);
}

/**
 * True for errors that come from a request we aborted on purpose
 * (component unmounted, newer request started) and need no reporting.
 *
 * @param {*} err
 * @returns {boolean}
 */
export function isAbortError(err) {
    return isCancel(err) || err?.name === "AbortError";
}
