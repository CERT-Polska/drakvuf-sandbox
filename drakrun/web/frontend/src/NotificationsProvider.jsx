import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { NotificationsContext } from "./notifications.js";
import { formatApiError, isAbortError } from "./errors.js";

const TOAST_TIMEOUT_MS = 10000;
const MAX_TOASTS = 5;

/**
 * Shows error toasts in the bottom right corner. Components report errors
 * with useNotifications().notifyError(err, title). Unhandled promise
 * rejections are reported as well, as a safety net.
 */
export function NotificationsProvider({ children }) {
    const [toasts, setToasts] = useState([]);
    const nextId = useRef(0);
    const timers = useRef(new Map());

    const dismiss = useCallback((id) => {
        clearTimeout(timers.current.get(id));
        timers.current.delete(id);
        setToasts((current) => current.filter((t) => t.id !== id));
    }, []);

    const notifyError = useCallback(
        (err, title = "Error") => {
            if (isAbortError(err)) {
                return;
            }
            console.error(title, err);
            const id = nextId.current++;
            const message = formatApiError(err);
            setToasts((current) =>
                [...current, { id, title, message }].slice(-MAX_TOASTS),
            );
            timers.current.set(
                id,
                setTimeout(() => dismiss(id), TOAST_TIMEOUT_MS),
            );
        },
        [dismiss],
    );

    useEffect(() => {
        const onUnhandledRejection = (event) => {
            notifyError(event.reason, "Unexpected error");
        };
        window.addEventListener("unhandledrejection", onUnhandledRejection);
        const pending = timers.current;
        return () => {
            window.removeEventListener(
                "unhandledrejection",
                onUnhandledRejection,
            );
            pending.forEach((timer) => clearTimeout(timer));
            pending.clear();
        };
    }, [notifyError]);

    const contextValue = useMemo(() => ({ notifyError }), [notifyError]);

    return (
        <NotificationsContext.Provider value={contextValue}>
            {children}
            <div
                className="toast-container position-fixed bottom-0 end-0 p-3"
                aria-live="assertive"
                aria-atomic="false"
            >
                {toasts.map((toast) => (
                    <div
                        key={toast.id}
                        className="toast show"
                        role="alert"
                        aria-atomic="true"
                    >
                        <div className="toast-header text-bg-danger">
                            <strong className="me-auto">{toast.title}</strong>
                            <button
                                type="button"
                                className="btn-close btn-close-white"
                                aria-label="Close"
                                onClick={() => dismiss(toast.id)}
                            ></button>
                        </div>
                        <div className="toast-body text-break">
                            {toast.message}
                        </div>
                    </div>
                ))}
            </div>
        </NotificationsContext.Provider>
    );
}
