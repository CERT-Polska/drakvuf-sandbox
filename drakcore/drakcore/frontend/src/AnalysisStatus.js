import React from "react";
import { Component } from "react";
import { Redirect } from "react-router-dom";
import "./App.css";
import api from "./api";
import RFB from '@novnc/novnc'

class PasswordField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      value: "",
    };

    this.handleInput = this.handleInput.bind(this);
  }

  handleInput(event) {
    if (event.target.name === "password")
      this.setState({ value: event.target.value });
    this.props.onInput(event);
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
            onChange={this.handleInput}
          />
          <button
            type="button"
            name="submit"
            className="btn btn-primary"
            onClick={this.handleInput}
          >Open VNC</button>
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
      error: null,
      vnc_started: false,
      updated: false,
    };

    this.timerID = null;

    this.handleInput = this.handleInput.bind(this);
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
          updated: true,
          spinner: newSpinner,
        });
      }
    }, 1000);
  }

  createConnection() {
    let rfb = null
    try {
      rfb = new RFB(document.getElementById('noVNC-canvas'), `ws://:6301`, { credentials: { password: this.state.password }})
      rfb.addEventListener('connect', () => {
          this.setState({ vnc_started: true, error: null });
          rfb.focus();
          const canvas = document.getElementById("noVNC-canvas").firstChild.firstChild;
          canvas.style.width = "auto";
          canvas.style.height = "auto";
      });
      rfb.addEventListener('disconnect', () => this.setState({ vnc_started: false }));
      rfb.addEventListener('securityfailure', (err) => this.setState({ error: err.detail.reason }))  // TODO: show error
      rfb.scaleViewport = true;
      rfb.resizeSession = true;
    } catch (err) {
      console.error(`Unable to create RFB client: ${err}`)
    }
  
    return rfb
  }

  componentWillUnmount() {
    if (this.timerID) {
      clearTimeout(this.timerID);
    }
  }

  handleInput(event) {
    if (event.target.name === "password")
      this.setState({ password: event.target.value });
    else if (event.target.name === "submit")
      this.createConnection();
    else
      console.log("Unexpected event: ", event);
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

        <br/>

        <PasswordField
            label="VNC password"
            onInput={this.handleInput}
            placeholder="password"
            hint="VNC password is generated once for all VMs and can be checked via 'drak-vncpasswd' command"
            style={{ display: this.state.vnc_started ? 'none' : 'block' }}
        />

        { this.state.error && <div className="alert alert-danger">{ this.state.error }</div> }

        <div id='noVNC-canvas' style={{display: this.state.vnc_started ? 'block' : 'none'}} />
      </div>
    );
  }
}

export default AnalysisStatus;
