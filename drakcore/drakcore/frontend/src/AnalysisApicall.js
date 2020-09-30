import React from "react";
import { Component } from "react";
import "./App.css";
import api from "./api";
import OptionPicker from "./OptionPicker";

class AnalysisApicall extends Component {
  constructor(props) {
    super(props);

    this.analysis_id = this.props.match.params.analysis;
    const pid = parseInt(this.props.match.params.pid);

    this.state = {
      calls: null,
      processList: [],
      selectedPid: pid || null,
    };

    this.pidChanged = this.pidChanged.bind(this);
  }

  async pidChanged(new_pid) {
    try {
      this.setState({ calls: null, selectedPid: parseInt(new_pid) });
      const res = await api.getApiCalls(this.analysis_id, new_pid);
      const calls = res.data.split("\n").map(JSON.parse);
      this.setState({ calls });
    } catch (e) {
      this.setState({ calls: [] });
    }
  }

  async componentDidMount() {
    const analysis = this.props.match.params.analysis;
    const process_tree = await api.getProcessTree(analysis);

    function treeFlatten(process_tree) {
      let result = [];

      process_tree.forEach((proc) => {
        result.push({
          key: proc.pid,
          value: `${proc.pid} – ${proc.procname || "unnamed process"}`,
        });
        result.push(...treeFlatten(proc.children));
      });

      result.sort((a, b) => a.pid - b.pid);

      return result;
    }

    if (process_tree) {
      this.setState({ processList: treeFlatten(process_tree.data) });

      const pid = parseInt(this.props.match.params.pid);
      this.pidChanged(pid);
    }
  }

  render() {
    let content;
    if (this.state.calls === null) {
      content = (
        <div
          className="alert alert-primary d-flex align-items-center"
          role="alert"
        >
          Loading....
          <div
            className="spinner-border ml-auto"
            role="status"
            aria-hidden="true"
          ></div>
        </div>
      );
    } else if (this.state.calls.length === 0) {
      content = (
        <div className="alert alert-primary" role="alert">
          No API calls found for this process
        </div>
      );
    } else {
      let tableContent = this.state.calls.map((entry, i) => (
        <tr key={i}>
          <td>{entry.timestamp}</td>
          <td>
            <code>{entry.method}</code>
          </td>
          <td>
            {entry.arguments.map((arg, i) => (
              <div key={i} className="badge-outline-primary badge mr-1">
                {arg}
              </div>
            ))}
          </td>
        </tr>
      ));
      content = (
        <table className="table table-centered apicallTable">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Method</th>
              <th>Arguments</th>
            </tr>
          </thead>
          <tbody>{tableContent}</tbody>
        </table>
      );
    }

    return (
      <div className="App container-fluid">
        <div className="page-title-box">
          <h4 className="page-title">API calls</h4>
        </div>

        <div className="card tilebox-one">
          <div className="card-body">
            <OptionPicker
              selected={this.state.selectedPid}
              data={this.state.processList}
              onChange={this.pidChanged}
              className="mb-1"
            />
            {content}
          </div>
        </div>
      </div>
    );
  }
}

export default AnalysisApicall;
