import React from "react";
import { Component } from "react";
import "./App.css";
import api from "./api";

class UploadSample extends Component {
  constructor(props) {
    super(props);
    this.state = {
      file: null,
    };

    this.onFileChange = this.onFileChange.bind(this);
    this.onSubmit = this.onSubmit.bind(this);
  }

  onFileChange(event) {
    event.preventDefault();
    this.setState({ file: event.target.files[0] });
  }

  async onSubmit(event) {
    event.preventDefault();
    if (this.state.file === null) return;
    let response = await api.uploadSample(this.state.file);
    this.props.history.push(`/progress/${response.data.task_uid}`);
  }

  render() {
    return (
      <div className="App container-fluid">
        <div className="page-title-box">
          <h4 className="page-title">Upload sample</h4>
        </div>

        <form onSubmit={this.onSubmit}>
          <input type="file" name="file" onChange={this.onFileChange} />
          <button type="submit">Upload</button>
        </form>
      </div>
    );
  }
}

export default UploadSample;
