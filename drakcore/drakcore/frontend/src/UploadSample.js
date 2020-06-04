import React from "react";
import { Component } from "react";
import "./App.css";
import api from "./api";

class OptionalField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      value: "",
    };

    this.handleInput = this.handleInput.bind(this);
  }

  handleInput(event) {
    this.setState({ value: event.target.value });
    this.props.onInput(event);
  }

  render() {
    return (
      <div className="form-group">
        <label>{this.props.label}</label>
        <div className="input-group">
          <div className="input-group-prepend">
            <div className="input-group-text">
              <input
                type="checkbox"
                checked={this.state.value !== ""}
                readOnly
              />
            </div>
          </div>
          <input
            type="text"
            name={this.props.name}
            className="form-control"
            placeholder={this.props.placeholder}
            onChange={this.handleInput}
          />
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

class MinuteSlider extends Component {
  render() {
    return (
      <input
        onInput={this.props.onInput}
        className="custom-range"
        type="range"
        name={this.props.name}
        min={60 * this.props.min}
        max={60 * this.props.max}
        step={60}
        defaultValue={60 * this.props.default}
      />
    );
  }
}

class UploadSample extends Component {
  constructor(props) {
    super(props);
    this.state = {
      file: null,
      customFileName: "",
      customStartCmd: "",
      timeout: 10 * 60,

      error: null,
      uploadInProgress: false,
    };

    this.handleSubmit = this.handleSubmit.bind(this);
    this.handleInput = this.handleInput.bind(this);
    this.formValid = this.formValid.bind(this);
    this.setError = this.setError.bind(this);
  }

  setError(newError) {
    this.setState({ error: newError });
  }

  formValid() {
    let errMsg = null;

    if (this.state.file === null) {
      errMsg = "Choose a file";
    }

    const hasCustomFileName = this.state.customFileName !== "";
    const hasCustomStartCmd = this.state.customStartCmd !== "";

    if (hasCustomFileName) {
      const fname = this.state.customFileName;
      // Check for whitespace
      if (!fname.match(/^\S+$/)) {
        errMsg = "File name contains invalid characters";
      } else if (!fname.match(/^[\w]+\.(?:dll|exe)$/i)) {
        errMsg = "Invalid file name. Only .dll and .exe files are supported";
      }
    }

    if (hasCustomStartCmd) {
      const startCmd = this.state.customStartCmd;
      if (!startCmd.includes("%f")) {
        errMsg = "Sample name (%f) was not found in start command";
      }
    }

    if (errMsg !== null) {
      this.setError(errMsg);
      return false;
    }
    return true;
  }

  async handleSubmit(event) {
    event.preventDefault();
    if (!this.formValid()) {
      return;
    }
    this.setState({ uploadInProgress: true });

    try {
      let options = {};
      options.timeout = this.state.timeout;
      if (this.state.customFileName !== "") {
        options.file_name = this.state.customFileName;
      }
      if (this.state.customStartCmd !== "") {
        options.start_command = this.state.customStartCmd;
      }

      let response = await api.uploadSample(this.state.file, options);
      this.props.history.push(`/progress/${response.data.task_uid}`);
    } catch (error) {
      this.setState({ uploadInProgress: false });
      this.setError("Unable to upload sample for analysis");
    }
  }

  handleInput(event) {
    this.setState({ error: null });
    const field = event.target.name;
    switch (field) {
      case "file":
        this.setState({ file: event.target.files[0] });
        break;
      case "analysisTime":
        this.setState({ timeout: event.target.value });
        break;
      case "startCommand":
        this.setState({ customStartCmd: event.target.value });
        break;
      case "fileName":
        this.setState({ customFileName: event.target.value });
        break;
      default:
        console.log("Unexpected field name: ", field);
    }
  }

  render() {
    let error;
    if (this.state.error !== null) {
      error = (
        <div className="alert alert-danger" role="alert">
          <strong>Error</strong> - {this.state.error}
        </div>
      );
    }

    const uploadSpinner = (
      <span
        className="spinner-border spinner-border-sm mr-1"
        role="status"
        aria-hidden="true"
      ></span>
    );

    return (
      <div className="App container-fluid">
        <div className="page-title-box">
          <h4 className="page-title">Upload sample</h4>
        </div>

        {error}

        <form onSubmit={this.handleSubmit}>
          <div className="form-group">
            <label>Sample file</label>
            <div className="custom-file">
              <label className="custom-file-label" htmlFor="sampleFile">
                {this.state.file ? this.state.file.name : "Choose a file"}
              </label>
              <input
                type="file"
                name="file"
                id="sampleFile"
                className="custom-file-input"
                onChange={this.handleInput}
                required
              />
            </div>
          </div>
          <div className="form-group">
            <label htmlFor="analysisTime">Analysis time</label>
            <MinuteSlider
              min={1}
              max={10}
              default={10}
              name="analysisTime"
              onInput={this.handleInput}
            />
            <small>{this.state.timeout / 60} min</small>
          </div>
          <div className="collapse" id="customOptions">
            <OptionalField
              label="File name"
              onInput={this.handleInput}
              name="fileName"
              placeholder="e.g. malware.exe or malware.dll"
            />
            <OptionalField
              label="Start command"
              onInput={this.handleInput}
              name="startCommand"
              placeholder="eg. start %f"
              hint="%f will be replaced by file name"
            />
          </div>
          <div className="form-group">
            <button
              type="submit"
              className="btn btn-primary mr-2"
              value="Upload"
              disabled={this.state.uploadInProgress}
            >
              {this.state.uploadInProgress ? uploadSpinner : ""}
              Upload
            </button>
            <button
              type="button"
              className="btn btn-primary"
              data-toggle="collapse"
              data-target="#customOptions"
            >
              Customize
            </button>
          </div>
        </form>
      </div>
    );
  }
}

export default UploadSample;
