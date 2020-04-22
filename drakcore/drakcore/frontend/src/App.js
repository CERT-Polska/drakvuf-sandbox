import React from "react";
import {Component} from 'react';
import {
    BrowserRouter as Router,
    Switch,
    Route,
    Link,
    withRouter
} from "react-router-dom";
import AnalysisList from "./AnalysisList";
import AnalysisMain from "./AnalysisMain";
import AnalysisStatus from "./AnalysisStatus";


class NavBtns extends Component {
    render() {
        let analysis_id = null;

        if (this.props.location.pathname.startsWith("/analysis/")) {
            analysis_id = this.props.location.pathname.split("/")[2];
        }

        let nav_btns = <div/>;

        if (analysis_id) {
            nav_btns = <div>
                <li className="side-nav-title side-nav-item">Analysis</li>
                <li className="side-nav-item">
                    <Link to={"/analysis/" + analysis_id} className="side-nav-link">
                        <i className="uil-clipboard-alt"/>
                        <span> Report </span>
                    </Link>
                </li>
            </div>;
        }

        return nav_btns;
    }
}


class App extends Component {
    render() {
        const NavBtnsWithRouter = withRouter(NavBtns);

        return <Router>
            <div className="wrapper">
                <div className="left-side-menu">
                    <a href="index.html" className="logo text-center logo-light">
                        <span className="logo-lg">
                            <img src="assets/images/logo.png" alt=""/>
                        </span>
                        <span className="logo-sm">
                            <img src="assets/images/logo.png" alt="" height="16"/>
                        </span>
                    </a>

                    <div className="h-100" id="left-side-menu-container" data-simplebar>
                        <ul className="metismenu side-nav">
                            <li className="side-nav-title side-nav-item">Sandbox</li>
                            <li className="side-nav-item">
                                <Link to={"/"} className="side-nav-link">
                                    <i className="uil-file-upload"/>
                                    <span> Upload sample </span>
                                </Link>
                            </li>
                            <li className="side-nav-item">
                                <Link to={"/"} className="side-nav-link">
                                    <i className="uil-folder"/>
                                    <span> Analyses </span>
                                </Link>
                            </li>

                            <NavBtnsWithRouter/>
                        </ul>
                        <div className="clearfix"/>
                    </div>

                </div>
            </div>

            <div className="content-page">
                <div className="content">
                    <Switch>
                        <Route path="/progress/:analysis" component={AnalysisStatus}/>
                        <Route path="/analysis/:analysis" component={AnalysisMain}/>
                        <Route path="/" exact component={AnalysisList}/>
                    </Switch>
                </div>
            </div>

        </Router>;
    }
}

export default App;
