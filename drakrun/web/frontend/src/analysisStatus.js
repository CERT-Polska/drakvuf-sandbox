export function isStatusPending(status) {
    return status === "queued" || status === "started";
}

export function isStatusFinal(status) {
    return status === "finished" || status === "failed";
}
