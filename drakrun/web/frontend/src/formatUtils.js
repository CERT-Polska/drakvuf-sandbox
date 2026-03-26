/**
 * Format a javascript Date object into human-readable format.
 *
 * The date format is "2026-03-26 12:23:43".
 * For null, this function returns "-"
 *
 * @param {?Date} date Javascript Date object. Can be null.
 * @returns {String} Pretty printed date object
 */
export function formatDate(date) {
    if (date === null) {
        return "-";
    }
    // Slightly hacky - sv-SE uses the time format we want (yyyy-mm-dd), but - unlike
    // toISOString() - it uses local time.
    return date.toLocaleString("sv-SE");
}

/**
 * Create a javascript Date object from Unix timestamp
 *
 * @param {number} timestamp Unix timestmap
 * @returns {Date}
 */
export function fromTimestamp(timestamp) {
    return new Date(timestamp * 1000);
}
