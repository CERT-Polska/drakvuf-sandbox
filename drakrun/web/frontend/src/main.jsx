import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import "bootstrap";
import "bootstrap/dist/css/bootstrap.css";

import App from "./App.jsx";
import { BrowserRouter } from "react-router-dom";
import { NotificationsProvider } from "./NotificationsProvider.jsx";

createRoot(document.getElementById("root")).render(
    <StrictMode>
        <BrowserRouter>
            <NotificationsProvider>
                <App />
            </NotificationsProvider>
        </BrowserRouter>
    </StrictMode>,
);
