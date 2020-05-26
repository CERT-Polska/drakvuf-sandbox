import React from "react";
import { Component } from "react";
import "./App.css";
import api from "./api";

class UploadSample extends Component {
  constructor(props) {
    super(props);
    this.state = {
      file: null,
      timeout: 10 * 60,
    };

    this.onFileChange = this.onFileChange.bind(this);
    this.onSubmit = this.onSubmit.bind(this);
    this.onInput = this.onInput.bind(this);
  }

  onFileChange(event) {
    event.preventDefault();
    this.setState({ file: event.target.files[0] });
  }

  async onSubmit(event) {
    event.preventDefault();
    if (this.state.file === null) return;
    let response = await api.uploadSample(this.state.file, this.state.timeout);
    this.props.history.push(`/progress/${response.data.task_uid}`);
  }

  onInput(event) {
    this.setState({ timeout: event.target.value });
  }

  render() {
    return (
      <div className="App container-fluid">
        <div className="page-title-box">
          <h4 className="page-title">Upload sample</h4>
        </div>

        <form onSubmit={this.onSubmit} className="form-horizontal col-lg-5">
          <div className="form-group">
            <div className="custom-file">
              <label className="custom-file-label" htmlFor="sampleFile">
                {this.state.file ? this.state.file.name : "Choose file"}
              </label>
              <input
                type="file"
                name="file"
                id="sampleFile"
                className="custom-file-input"
                onChange={this.onFileChange}
                required
              />
            </div>
          </div>
          <div className="form-group">
            <input
              onInput={this.onInput}
              className="custom-range col-10"
              id="example-range"
              type="range"
              name="range"
              min={60}
              max={10 * 60}
              step={60}
              defaultValue={this.state.timeout}
            />
            <output
              className="col-2"
              style={{ textAlign: "center" }}
              name="timeoutValue"
            >
              {this.state.timeout / 60} min
            </output>
          </div>
          <div className="form-group">
            <button type="submit" className="btn btn-primary">
              Upload
            </button>
          </div>
        </form>
      </div>
    );
  }
}

export default UploadSample;
