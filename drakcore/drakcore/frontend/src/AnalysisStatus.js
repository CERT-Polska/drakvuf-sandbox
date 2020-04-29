import React from "react";
import { Component } from "react";
import { Redirect } from "react-router-dom";
import "./App.css";
import api from "./api";

class AnalysisStatus extends Component {
  constructor(props) {
    super(props);

    this.state = {
      status: "unknown",
      spinner: "oO",
      updated: false,
    };

    this.timerID = null;
  }

  componentDidMount() {
    if (this.timerID) {
      return;
    }

    this.timerID = setInterval(async () => {
      const response = await api.getStatus(this.props.match.params.analysis);
      if (response.data) {
        let newSpinner = this.state.spinner === "oO" ? "Oo" : "oO";
        this.setState({
          status: response.data.status,
          updated: true,
          spinner: newSpinner,
        });
      }
    }, 1000);
  }

  componentWillUnmount() {
    if (this.timerID) {
      clearTimeout(this.timerID);
    }
  }

  render() {
    if (this.state.status === "done") {
      return <Redirect to={"/analysis/" + this.props.match.params.analysis} />;
    }

    return (
      <div className="App container-fluid">
        <div className="page-title-box">
          <h4 className="page-title">Status</h4>
        </div>

        <p>Please wait until analysis is completed (usually 10 minutes).</p>
        <p>
          Current status: {this.state.status}... {this.state.spinner}
        </p>

        <div className="progress">
          <div
            className="progress-bar progress-bar-striped progress-bar-animated"
            style={{ width: "100%" }}
          />
        </div>
      </div>
    );
  }
}

export default AnalysisStatus;
