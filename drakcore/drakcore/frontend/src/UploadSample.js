import React from "react";
import { Component } from "react";
import "./App.css";

class UploadSample extends Component {
  render() {
    return (
      <div className="App container-fluid">
        <div className="page-title-box">
          <h4 className="page-title">Upload sample</h4>
        </div>

        <form action="/upload" method="POST" encType="multipart/form-data">
          <input type="file" name="file" />
          <button type="submit">Upload</button>
        </form>
      </div>
    );
  }
}

export default UploadSample;
