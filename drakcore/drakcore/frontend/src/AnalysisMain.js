import React from "react";
import { Component } from "react";
import { Link } from "react-router-dom";
import "./App.css";
import api from "./api";
import { Graphviz } from "graphviz-react";

class AnalysisMain extends Component {
  constructor(props) {
    super(props);

    this.state = {
      logs: [],
      graph: null,
      graphState: "loading",
      processTree: null,
    };
    this.analysisID = this.props.match.params.analysis;
    this.processTreeHelper = this.processTreeHelper.bind(this);
  }

  processTreeHelper(process) {
    return (
      <React.Fragment key={process.pid}>
        <li>
          <code>{process.procname ? process.procname : "unnamed process"}</code>
          <span className="ml-1">
            (
            <Link to={`/analysis/${this.analysisID}/apicalls/${process.pid}`}>
              {process.pid}
            </Link>
            )
          </span>
        </li>
        {this.buildProcessTree(process.children)}
      </React.Fragment>
    );
  }

  buildProcessTree(proclist) {
    return (
      <ul>
        {proclist
          .slice()
          .sort((pA, pB) => pA.pid - pB.pid)
          .map(this.processTreeHelper)}
      </ul>
    );
  }

  async componentDidMount() {
    const res_logs = await api.listLogs(this.analysisID);
    if (res_logs.data) {
      this.setState({ logs: res_logs.data });
    }

    try {
      const res_graph = await api.getGraph(this.analysisID);
      if (res_graph.data) {
        this.setState({ graphState: "loaded", graph: res_graph.data });
      } else {
        this.setState({ graphState: "missing" });
      }
    } catch (e) {
      this.setState({ graphState: "missing" });
    }

    const process_tree = await api.getProcessTree(this.analysisID);
    if (process_tree) {
      this.setState({ processTree: process_tree.data });
    }
  }

  getPathWithoutExt(path) {
    // strip file extension from the path (assuming it's always present)
    return path.split(".").slice(0, -1).join(".");
  }

  getFileNameWithoutExt(path) {
    return this.getPathWithoutExt(path).split("/").slice(-1).pop();
  }

  render() {
    let processTree = <div>Loading graph...</div>;

    if (this.state.graphState === "loaded") {
      processTree = (
        <div id="treeWrapper">
          <Graphviz
            dot={this.state.graph}
            options={{ zoom: true, width: "100%" }}
          />
        </div>
      );
    } else if (this.state.graphState === "missing") {
      processTree = (
        <div>
          (Process tree was not generated, please check out "ProcDOT integration
          (optional)" section of README to enable it.)
        </div>
      );
    }

    let simpleProcessTree;

    if (this.state.processTree) {
      simpleProcessTree = (
        <div className="card tilebox-one">
          <div className="card-body">
            <h5 className="card-title mb-0">Proces tree</h5>
            {this.buildProcessTree(this.state.processTree)}
          </div>
        </div>
      );
    }

    return (
      <div className="App container-fluid">
        <div className="page-title-box">
          <h4 className="page-title">Report</h4>
        </div>

        <div className="card tilebox-one">
          <div className="card-body">
            <h5 className="card-title mb-0">Behavioral graph</h5>

            {processTree}
          </div>
        </div>

        {simpleProcessTree}

        <div className="row">
          <div className="col-md-9">
            <div className="card tilebox-one">
              <div className="card-body">
                <h5 className="card-title mb-0">Analysis logs</h5>

                <div className="list-group">
                  {this.state.logs.map((val) => {
                    return (
                      <a
                        key={val}
                        href={`/logs/${this.getPathWithoutExt(val)}`}
                        className="list-group-item list-group-item-action"
                      >
                        {this.getFileNameWithoutExt(val)}
                      </a>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>

          <div className="col-md-3">
            <div class="card">
              <a href={`/dumps/${this.analysisID}`} className="btn btn-primary">
                <i class="mdi mdi-download mr-2"></i>
                <span>Download dumps</span>
              </a>
            </div>
          </div>
        </div>
      </div>
    );
  }
}

export default AnalysisMain;
