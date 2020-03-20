import React from "react";
import { Component } from "react";
import { Link } from "react-router-dom";
import "./App.css";
import api from "./api";

class AnalysisList extends Component {
    constructor(props) {
        super(props);

        this.state = {
            analyses: []
        };
    }

    async componentDidMount() {
        const response = await api.getList();
        if (response.data)
            this.setState({ analyses: response.data });
    }

    render() {
        return <div className="App container-fluid">
            <h2>Upload</h2>
            <form action="/upload" method="POST" encType="multipart/form-data">
                <input type="file" name="file" />
                <button type="submit">Upload</button>
            </form>

            <h2>Analyses</h2>
            <table className="table table-striped table-bordered">
                <thead>
                    <tr>
                        <th>Analysis</th>
                    </tr>
                </thead>
                <tbody>
                {
                    this.state.analyses.map((val) => {
                        return <tr>
                            <td><Link to={"/analysis/" + val.id}>{val.id}</Link></td>
                        </tr>;
                    })
                }
                </tbody>
            </table>
        </div>;
    }
}

export default AnalysisList;
