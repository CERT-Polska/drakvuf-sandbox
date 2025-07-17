import { useCallback, useRef, useState } from "react";
import RFB from "@novnc/novnc";

let VNC_HOSTNAME;
if (import.meta.env.VITE_API_SERVER) {
    VNC_HOSTNAME = new URL(import.meta.env.VITE_API_SERVER).hostname;
} else {
    VNC_HOSTNAME = window.location.hostname;
}

function connectVNC(url, password, canvas, onDisconnect) {
    return new Promise((resolve, reject) => {
        try {
            const rfb = new RFB(
                canvas,
                url,
                password ? { credentials: { password } } : {},
            );
            rfb.addEventListener("connect", () => {
                resolve(rfb);
                rfb.focus();
            });
            rfb.addEventListener("credentialsrequired", (err) => {
                reject({ error: "credentialsrequired", detail: err });
            });
            rfb.addEventListener("disconnect", (err) => {
                onDisconnect({ error: "disconnected", detail: err });
            });
            rfb.addEventListener("securityfailure", (err) => {
                reject({ error: "securityfailure", detail: err });
            });
            rfb.scaleViewport = true;
            rfb.resizeSession = true;
        } catch (err) {
            reject({ error: "exception", err });
        }
    });
}

export function PasswordForm({ onSubmit }) {
    const [password, setPassword] = useState("");
    return (
        <form
            onSubmit={(ev) => {
                ev.preventDefault();
                onSubmit(password);
            }}
        >
            <div className="mb-3">
                <label className="form-label">VNC Password</label>
                <input
                    type="password"
                    className="form-control"
                    id="vncPassword"
                    value={password}
                    onChange={(ev) => setPassword(ev.target.value)}
                />
            </div>
            <button type="submit" className="btn btn-primary">
                Connect
            </button>
        </form>
    );
}

export function AnalysisLiveInteraction({ vmId }) {
    const [error, setError] = useState(null);
    const [password, setPassword] = useState(
        sessionStorage.getItem("vncPassword"),
    );
    const canvas = useRef(null);
    const rfb = useRef(null);

    const disconnect = useCallback((reason) => {
        console.log(`VNC disconnected because of`, reason);
        rfb.current = null;
        setError(reason);
    }, []);
    const connect = useCallback(
        async (password) => {
            try {
                canvas.current.textContent = "";
                rfb.current = await connectVNC(
                    `ws://${VNC_HOSTNAME}:${6400 + vmId}`,
                    password,
                    canvas.current,
                    disconnect,
                );
                setError(null);
            } catch (e) {
                disconnect(e);
            }
        },
        [disconnect, vmId],
    );
    const setCanvas = useCallback(
        (newCanvas) => {
            if (canvas.current && rfb.current) {
                rfb.current.disconnect();
            }
            if (newCanvas) {
                canvas.current = newCanvas;
                connect(password);
            }
            canvas.current = newCanvas;
        },
        [connect, password],
    );
    const onSubmit = useCallback(
        (passwordInput) => {
            sessionStorage.setItem("vncPassword", passwordInput);
            setPassword(passwordInput);
            connect(passwordInput);
        },
        [connect],
    );
    return (
        <div>
            {error ? (
                <div className="text-danger text-center">
                    Error: {error.error}
                </div>
            ) : (
                []
            )}
            {error?.error === "credentialsrequired" || error?.error === "securityfailure" ? (
                <PasswordForm onSubmit={onSubmit} />
            ) : (
                []
            )}
            <div
                ref={setCanvas}
                style={{
                    width: "800px",
                    height: "600px",
                    resize: "both",
                    overflow: "auto",
                }}
            ></div>
        </div>
    );
}
