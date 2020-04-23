import React from 'react';
import {Component} from 'react';
import './App.css';
import api from './api';
import {Graphviz} from 'graphviz-react';

class AnalysisMain extends Component {
    constructor(props) {
        super(props);

        this.state = {
            "logs": [],
            "graph": null
        };
    }

    async componentDidMount() {
        const res_logs = await api.listLogs(this.props.match.params.analysis);
        if (res_logs.data) {
            this.setState({"logs": res_logs.data});
        }

        const res_graph = await api.getGraph(this.props.match.params.analysis);
        if (res_graph.data) {
            this.setState({"graph": res_graph.data});
        }
    }

    getPathWithoutExt(path) {
        // strip file extension from the path (assuming it's always present)
        return path.split('.').slice(0, -1).join('.');
    }

    getFileNameWithoutExt(path) {
        return this.getPathWithoutExt(path).split('/').slice(-1).pop();
    }

    render() {
        let processTree = <div>(Process tree was not generated, please check out "ProcDOT integration (optional)"
            section of README to enable it.)</div>;

        if (this.state.graph) {
            processTree = <div id="treeWrapper" style={{width: '80em', height: '30em'}}>
                <Graphviz dot={this.state.graph}/>
            </div>;
        }

        return <div className="App container-fluid">
            <div className="page-title-box">
                <h4 className="page-title">Report</h4>
            </div>

            <div className="card mb-md-0 mb-3">
                <div className="card-body">
                    <h5 className="card-title mb-0">Behavioral graph</h5>

                    {processTree}
                </div>
            </div>

            <div className="card mb-md-0 mb-3">
                <div className="card-body">
                    <h5 className="card-title mb-0">Analysis logs</h5>

                    <div className="list-group">
                        {
                            this.state.logs.map(val => {
                                return <a href={`/logs/${this.getPathWithoutExt(val)}`}
                                          className="list-group-item list-group-item-action">
                                    {this.getFileNameWithoutExt(val)}</a>
                            })
                        }
                    </div>
                </div>
            </div>
        </div>;
    }
}

export default AnalysisMain;
