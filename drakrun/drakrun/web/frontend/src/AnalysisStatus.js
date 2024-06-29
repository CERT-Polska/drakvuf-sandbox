import React from "react";
import { Component, createRef } from "react";
import { Redirect } from "react-router-dom";
import "./App.css";
import api from "./api";
import RFB from "@novnc/novnc";

class PasswordField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      value: "",
    };

    this.handlePassword = this.handlePassword.bind(this);
    this.handleSubmit = this.handleSubmit.bind(this);
  }

  handlePassword(event) {
    this.setState({ value: event.target.value });
    this.props.onInput(event);
  }

  handleSubmit(event) {
    this.props.onSubmit(event);
  }

  render() {
    return (
      <div className="form-group" style={this.props.style}>
        <label>{this.props.label}</label>
        <div className="input-group">
          <input
            type="password"
            name="password"
            className="form-control"
            placeholder={this.props.placeholder}
            onChange={this.handlePassword}
          />
          <button
            type="button"
            name="submit"
            className="btn btn-primary"
            onClick={this.handleSubmit}
          >
            Open VNC
          </button>
        </div>
        {this.props.hint !== undefined ? (
          <small className="form-text text-muted">{this.props.hint}</small>
        ) : (
          ""
        )}
      </div>
    );
  }
}

class AnalysisStatus extends Component {
  constructor(props) {
    super(props);

    this.state = {
      status: "unknown",
      spinner: "oO",
      password: "",
      vnc_port: null,
      error: null,
      vnc_started: false,
      updated: false,
    };

    this.novnc_canvas = createRef();
    this.timerID = null;

    this.handlePassword = this.handlePassword.bind(this);
    this.createConnection = this.createConnection.bind(this);
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
          vnc_port: 6400 + parseInt(response.data.vm_id),
          updated: true,
          spinner: newSpinner,
        });
      }
    }, 1000);
  }

  createConnection() {
    try {
      const rfb = new RFB(
        this.novnc_canvas.current,
        `ws://${window.location.hostname}:${this.state.vnc_port}`,
        { credentials: { password: this.state.password } }
      );
      rfb.addEventListener("connect", () => {
        this.setState({ vnc_started: true, error: null });
        rfb.focus();
        const canvas = this.novnc_canvas.current.firstChild.firstChild;
        canvas.style.width = "auto";
        canvas.style.height = "auto";
      });
      rfb.addEventListener("disconnect", () =>
        this.setState({ vnc_started: false })
      );
      rfb.addEventListener("securityfailure", (err) =>
        this.setState({ error: err.detail.reason })
      ); // TODO: show error
      rfb.scaleViewport = true;
      rfb.resizeSession = true;
      return rfb;
    } catch (err) {
      console.error(`Unable to create RFB client: ${err}`);
    }
  }

  componentWillUnmount() {
    if (this.timerID) {
      clearTimeout(this.timerID);
    }
  }

  handlePassword(event) {
    this.setState({ password: event.target.value });
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

        <br />

        <PasswordField
          label="VNC password"
          onInput={this.handlePassword}
          onSubmit={this.createConnection}
          placeholder="password"
          hint="VNC password is generated once for all VMs and can be checked via 'drak-vncpasswd' command"
          style={{ display: this.state.vnc_started ? "none" : "block" }}
        />

        {this.state.error && (
          <div className="alert alert-danger">{this.state.error}</div>
        )}

        <div
          ref={this.novnc_canvas}
          style={{ display: this.state.vnc_started ? "block" : "none" }}
        />
      </div>
    );
  }
}

export default AnalysisStatus;
