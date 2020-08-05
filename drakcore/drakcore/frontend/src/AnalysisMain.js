import React from "react";
import { Component } from "react";
import { Link } from "react-router-dom";
import "./App.css";
import api from "./api";
import { Graphviz } from "graphviz-react";

function computeExpandState(expandPid, process, expandMap) {
  // compute the values for children
  process.children.forEach((child) =>
    computeExpandState(expandPid, child, expandMap)
  );

  // check if any of them is expanded
  const childrenExpanded = process.children.some(
    (child) => expandMap[child.pid]
  );

  // compute value for this process
  expandMap[process.pid] = childrenExpanded || process.pid === expandPid;
}

function formatTimestamp(ts) {
  return new Date(ts * 1000)
    .toISOString()
    .replace("T", " ")
    .replace(".000Z", "");
}

class ProcessTree extends Component {
  constructor(props) {
    super(props);

    this.toggleCollapse = this.toggleCollapse.bind(this);
    this.setExpanded = this.setExpanded.bind(this);
    this.buildProcessTree = this.buildProcessTree.bind(this);
    this.processTreeHelper = this.processTreeHelper.bind(this);
    this.isExpanded = this.isExpanded.bind(this);

    let initialExpandedMap = {};
    if (this.props.expandPid) {
      this.props.tree.forEach((process) =>
        computeExpandState(this.props.expandPid, process, initialExpandedMap)
      );
    }

    this.state = {
      expandedMap: initialExpandedMap,
    };
  }

  setExpanded(pid, value) {
    this.setState((oldState) => {
      const newState = {
        expandedMap: {
          ...oldState.expandedMap,
          [pid]: value,
        },
      };
      return newState;
    });
  }

  toggleCollapse(pid) {
    const current = this.state.expandedMap[pid];
    this.setExpanded(pid, !current);
  }

  isExpanded(pid) {
    return this.state.expandedMap[pid];
  }

  processTreeHelper(process) {
    const collapseType = this.isExpanded(process.pid)
      ? "mdi mdi-minus-circle mr-1"
      : "mdi mdi-plus-circle mr-1";
    const collapseToggle = (
      <span
        style={{ cursor: "pointer" }}
        className={collapseType}
        onClick={() => this.toggleCollapse(process.pid)}
      ></span>
    );

    const subtree = this.isExpanded(process.pid)
      ? this.buildProcessTree(process.children)
      : "";

    return (
      <React.Fragment key={process.pid}>
        <li>
          {process.children.length > 0 ? collapseToggle : ""}
          <code>{process.procname || "unnamed process"}</code>
          <span className="ml-1">
            (
            <Link
              to={`/analysis/${this.props.analysisID}/apicalls/${process.pid}`}
            >
              {process.pid}
            </Link>
            )
          </span>
        </li>
        {subtree}
      </React.Fragment>
    );
  }

  buildProcessTree(proclist) {
    return (
      <ul style={{ listStyleType: "none" }}>
        {proclist
          .slice()
          .sort((pA, pB) => pA.pid - pB.pid)
          .map(this.processTreeHelper)}
      </ul>
    );
  }

  render() {
    return this.buildProcessTree(this.props.tree);
  }
}

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null, errorInfo: null };
  }

  componentDidCatch(error, errorInfo) {
    this.setState({
      error: error,
      errorInfo: errorInfo,
    });
  }

  render() {
    if (this.state.errorInfo)
      return "cannot view graph due to malformed output";
    return this.props.children;
  }
}

class AnalysisMain extends Component {
  constructor(props) {
    super(props);

    this.state = {
      logs: [],
      graph: null,
      graphState: "loading",
      processTree: null,
      metadata: null,
    };

    this.analysisID = this.props.match.params.analysis;
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
    const inject_log = await api.getLog(this.analysisID, "inject");
    if (process_tree && inject_log) {
      const injectedPid = inject_log.data["InjectedPid"];
      this.setState({ processTree: process_tree.data, injectedPid });
    }

    const metadata = await api.getMetadata(this.analysisID);
    if (metadata.data) {
      this.setState({ metadata: metadata.data });
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
        <ErrorBoundary>
          <Graphviz
            dot={this.state.graph}
            options={{ zoom: true, width: "100%" }}
          />
        </ErrorBoundary>
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
            <ProcessTree
              tree={this.state.processTree}
              expandPid={this.state.injectedPid}
              analysisID={this.analysisID}
            />
          </div>
        </div>
      );
    }

    let metadata;
    if (this.state.metadata) {
      metadata = (
        <div background>
          <table className="table table-striped table-bordered">
            <tbody>
              <tr>
                <td>Sha256</td>
                <td>{this.state.metadata.sample_sha256}</td>
              </tr>
              <tr>
                <td>Magic bytes</td>
                <td>{this.state.metadata.magic_output}</td>
              </tr>
              <tr>
                <td>Start command</td>
                <td>{this.state.metadata.start_command}</td>
              </tr>
              <tr>
                <td>Started at</td>
                <td>{formatTimestamp(this.state.metadata.time_started)}</td>
              </tr>
              <tr>
                <td>Finished at</td>
                <td>{formatTimestamp(this.state.metadata.time_finished)}</td>
              </tr>
            </tbody>
          </table>
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
            <h5 className="card-title mb-0">Metadata</h5>

            {metadata}
          </div>
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
            <div className="card">
              <a href={`/dumps/${this.analysisID}`} className="btn btn-primary">
                <i className="mdi mdi-download mr-2"></i>
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
