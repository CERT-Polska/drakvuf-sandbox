import React from "react";
import { Component } from "react";
import {
  BrowserRouter as Router,
  Switch,
  Route,
  Link,
  withRouter,
} from "react-router-dom";
import AnalysisList from "./AnalysisList";
import AnalysisMain from "./AnalysisMain";
import AnalysisStatus from "./AnalysisStatus";
import AnalysisApicall from "./AnalysisApicall";
import UploadSample from "./UploadSample";

function AnalysisEntry(props) {
  return (
    <li className="side-nav-item">
      <Link to={props.url} className="side-nav-link">
        <i className={props.icon} />
        <span>{props.name}</span>
      </Link>
    </li>
  );
}

class NavBtns extends Component {
  render() {
    let analysis_id = null;

    if (this.props.location.pathname.startsWith("/analysis/")) {
      analysis_id = this.props.location.pathname.split("/")[2];
    }

    let nav_btns = <div />;

    if (analysis_id) {
      nav_btns = (
        <div>
          <li className="side-nav-title side-nav-item">Analysis</li>
          <AnalysisEntry
            name="Report"
            url={`/analysis/${analysis_id}`}
            icon="uil-clipboard-alt"
          />
          <AnalysisEntry
            name="API calls"
            url={`/analysis/${analysis_id}/apicalls`}
            icon="uil-heart-rate"
          />
        </div>
      );
    }

    return nav_btns;
  }
}

class App extends Component {
  render() {
    const NavBtnsWithRouter = withRouter(NavBtns);

    return (
      <Router>
        <div className="wrapper">
          <div className="left-side-menu">
            <a href="/" className="logo text-center logo-light">
              <span className="logo-lg">
                <img src="/assets/images/logo.png" alt="" />
              </span>
              <span className="logo-sm">
                <img src="/assets/images/logo.png" alt="" height="16" />
              </span>
            </a>

            <div className="h-100" id="left-side-menu-container" data-simplebar>
              <ul className="metismenu side-nav">
                <li className="side-nav-title side-nav-item">Sandbox</li>
                <li className="side-nav-item">
                  <Link to={"/upload"} className="side-nav-link">
                    <i className="uil-file-upload" />
                    <span> Upload sample </span>
                  </Link>
                </li>
                <li className="side-nav-item">
                  <Link to={"/"} className="side-nav-link">
                    <i className="uil-folder" />
                    <span> Analyses </span>
                  </Link>
                </li>

                <NavBtnsWithRouter />
              </ul>
              <div className="clearfix" />
            </div>
          </div>

          <div className="content-page">
            <div className="content">
              <Switch>
                <Route path="/progress/:analysis" component={AnalysisStatus} />
                <Route
                  path="/analysis/:analysis/apicalls/:pid?"
                  component={AnalysisApicall}
                />
                <Route path="/analysis/:analysis" component={AnalysisMain} />
                <Route path="/upload" exact component={UploadSample} />
                <Route path="/" exact component={AnalysisList} />
              </Switch>
            </div>
          </div>

          <footer className="footer">
            <div className="container-fluid">
              <div className="row">
                <div className="col-md-6">
                  DRAKVUF Sandbox (C) 2019-2020{" "}
                  <a href="https://cert.pl/">CERT Polska</a>
                  <br />
                  DRAKVUF (C) 2014-2020{" "}
                  <a href="https://tklengyel.com/">Tamas K Lengyel</a>
                </div>
                <div className="col-md-6">
                  <div className="text-md-right footer-links d-none d-md-block">
                    <a href="https://github.com/CERT-Polska/drakvuf-sandbox">
                      CERT-Polska / drakvuf-sandbox
                    </a>
                    <a href="https://github.com/tklengyel/drakvuf">
                      tklengyel / drakvuf
                    </a>
                  </div>
                </div>
              </div>
            </div>
          </footer>
        </div>
      </Router>
    );
  }
}

export default App;
