import React from 'react';
import {Component} from 'react';
import './App.css';
import api from './api';
import { Graphviz } from 'graphviz-react';

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

    render() {
        let processTree = <div>(Process tree was not generated, please check out <kbd>ProcDOT integration (optional)</kbd> section of README to enable it.)</div>;

        if (this.state.graph) {
            processTree = <div id="treeWrapper" style={{width: '80em', height: '30em'}}>
                <Graphviz dot={this.state.graph} />
            </div>;
        }

        return <div className="App container-fluid">
            {processTree}

            <h2>Logs</h2>
            <div className="list-group">
            {
                this.state.logs.map(val => {
                    return <a href={`/logs/${val.slice(0, -4)}`} class="list-group-item list-group-item-action">{val.slice(37, -4)}</a>
                })
            }
            </div>
        </div>;
    }
}

export default AnalysisMain;
