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

    formatTimestamp(ts) {
        return (new Date(ts * 1000)).toISOString()
            .replace('T', ' ')
            .replace('.000Z', '');
    }

    render() {
        return <div className="App container-fluid">

            <div className="page-title-box">
                <h4 className="page-title">Analyses</h4>
            </div>

            <table className="table table-striped table-bordered">
                <thead>
                    <tr>
                        <th>Analysis ID</th>
                        <th>Sample SHA256</th>
                        <th>Started</th>
                        <th>Finished</th>
                        <th>Start command</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                {
                    this.state.analyses.map((val) => {
                        return <tr>
                            <td className="text-hash"><Link to={"/analysis/" + val.id}>{val.id}</Link></td>
                            <td className="text-hash">{val.meta.sample_sha256}</td>
                            <td>{this.formatTimestamp(val.meta.time_started)}</td>
                            <td>{this.formatTimestamp(val.meta.time_finished)}</td>
                            <td><code>{val.meta.start_command}</code></td>
                            <td><Link className="btn btn-secondary" to={"/analysis/" + val.id}>
                                <i className="uil uil-document"/> View</Link></td>
                        </tr>;
                    })
                }
                </tbody>
            </table>
        </div>;
    }
}

export default AnalysisList;
