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

        let nav_btns = <ul className="navbar-nav mr-auto" />;

        if (analysis_id) {
            nav_btns = <ul className="navbar-nav mr-auto">
                <li className="nav-item">
                    <Link to={"/analysis/" + analysis_id} className="nav-link">Analysis</Link>
                </li>
            </ul>;
        }

        return nav_btns;
    }
}


class App extends Component {
    render() {
        const NavBtnsWithRouter = withRouter(NavBtns);

        return <Router>
            <div>
                <nav className="navbar navbar-expand-sm navbar-light bg-light">
                    <Link className="navbar-brand" to="/">DRAKVUF Sandbox</Link>
                    <button className="navbar-toggler" type="button" data-toggle="collapse"
                            data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent"
                            aria-expanded="false" aria-label="Toggle navigation">
                        <span className="navbar-toggler-icon" />
                    </button>

                    <div className="collapse navbar-collapse" id="navbarSupportedContent">
                        <NavBtnsWithRouter />
                    </div>
                </nav>

                <Switch>
                    <Route path="/progress/:analysis" component={AnalysisStatus} />
                    <Route path="/analysis/:analysis" component={AnalysisMain} />
                    <Route path="/" exact component={AnalysisList} />
                </Switch>
            </div>
        </Router>;
    }
}

export default App;
