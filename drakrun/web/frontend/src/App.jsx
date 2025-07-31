import React from "react";
import { Routes, Route, Link } from "react-router-dom";

import "./App.css";
import "startbootstrap-sb-admin/dist/css/styles.css";
import logo from "./assets/logo.png";
import AnalysisList from "./AnalysisList.jsx";
import UploadView from "./UploadView.jsx";
import AnalysisView from "./AnalysisView.jsx";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faFolder, faUpload, faGear } from "@fortawesome/free-solid-svg-icons";

function AppHeader() {
    return (
        <nav className="sb-topnav navbar navbar-expand navbar-dark bg-dark">
            <Link className="navbar-brand ps-3" to="/">
                <img alt="logo" src={logo} /> web
            </Link>
        </nav>
    );
}

function AppSidenav() {
    return (
        <div id="layoutSidenav_nav">
            <nav
                className="sb-sidenav accordion sb-sidenav-dark"
                id="sidenavAccordion"
            >
                <div className="sb-sidenav-menu">
                    <div className="nav">
                        <div className="sb-sidenav-menu-heading">Analysis</div>
                        <Link className="nav-link" to="/">
                            <div className="sb-nav-link-icon">
                                <FontAwesomeIcon icon={faFolder} />
                            </div>
                            Analyses
                        </Link>
                        <Link className="nav-link" to="/upload">
                            <div className="sb-nav-link-icon">
                                <FontAwesomeIcon icon={faUpload} />
                            </div>
                            Upload sample
                        </Link>
                        <div className="sb-sidenav-menu-heading">Sandbox</div>
                        <a className="nav-link" href="/openapi/swagger">
                            <div className="sb-nav-link-icon">
                                <FontAwesomeIcon icon={faGear} />
                            </div>
                            API docs
                        </a>
                        <a className="nav-link" href="/rq">
                            <div className="sb-nav-link-icon">
                                <FontAwesomeIcon icon={faGear} />
                            </div>
                            RQ Dashboard
                        </a>
                    </div>
                </div>
                <div className="sb-sidenav-footer">
                    <div className="small">{__APP_VERSION__}</div>
                </div>
            </nav>
        </div>
    );
}

function AppFooter() {
    return (
        <footer className="py-4 bg-light mt-auto">
            <div className="container-fluid px-4">
                <div className="d-flex flex-column small">
                    <div className="text-muted">
                        DRAKVUF Sandbox &copy; 2019-2025
                        <a
                            className="px-2 link-body-emphasis"
                            href="https://cert.pl/"
                        >
                            CERT Polska
                        </a>
                    </div>
                    <div className="text-muted">
                        DRAKVUF &reg; 2014-2025
                        <a
                            className="px-2 link-body-emphasis"
                            href="https://tklengyel.com/"
                        >
                            Tamas K Lengyel
                        </a>
                    </div>
                </div>
            </div>
        </footer>
    );
}

export default function App() {
    return (
        <>
            <AppHeader />
            <div id="layoutSidenav">
                <AppSidenav />
                <div id="layoutSidenav_content">
                    <main>
                        <Routes>
                            <Route path="/" element={<AnalysisList />} />
                            <Route path="/upload" element={<UploadView />} />
                            <Route
                                path="/analysis/:jobid"
                                element={<AnalysisView />}
                            />
                        </Routes>
                    </main>
                    <AppFooter />
                </div>
            </div>
        </>
    );
}
