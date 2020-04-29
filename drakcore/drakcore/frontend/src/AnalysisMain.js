import React from 'react';
import {Component} from 'react';
import './App.css';
import api from './api';
import {Graphviz} from 'graphviz-react';

function buildProcessTree(proclist) {
    return <ul>{proclist.slice().sort((pA, pB) => pA.pid - pB.pid).map(processTreeHelper)}</ul>;
}

function processTreeHelper(process) {
    return (
    <React.Fragment key={process.pid}>
        <li>
            <code>{process.procname ? process.procname : "unnamed process"}</code> ({process.pid})
        </li>
        {buildProcessTree(process.children)}
    </React.Fragment>);
}

class AnalysisMain extends Component {
    constructor(props) {
        super(props);

        this.state = {
            "logs": [],
            "graph": null,
            "processTree": null,
        };
    }

    async componentDidMount() {
        const analysis = this.props.match.params.analysis;
        const res_logs = await api.listLogs(analysis);
        if (res_logs.data) {
            this.setState({"logs": res_logs.data});
        }

        const res_graph = await api.getGraph(analysis);
        if (res_graph.data) {
            this.setState({"graph": res_graph.data});
        }

        const process_tree = await api.getProcessTree(analysis);
        if (process_tree) {
            this.setState({"processTree": process_tree.data});
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
        let simpleProcessTree;

        if (this.state.graph) {
            processTree = <div id="treeWrapper" style={{width: '80em', height: '30em'}}>
                <Graphviz dot={this.state.graph}/>
            </div>;
        } else if (this.state.processTree) {
            simpleProcessTree =
            <div className="card tilebox-one">
                <div className="card-body">
                    <h5 className="card-title mb-0">Proces tree</h5>
                    {buildProcessTree(this.state.processTree)}
                </div>
            </div>;
        }

        return <div className="App container-fluid">
            <div className="page-title-box">
                <h4 className="page-title">Report</h4>
            </div>

            <div className="card tilebox-one">
                <div className="card-body">
                    <h5 className="card-title mb-0">Behavioral graph</h5>

                    {processTree}
                </div>
            </div>

            {simpleProcessTree}

            <div className="card tilebox-one">
                <div className="card-body">
                    <h5 className="card-title mb-0">Analysis logs</h5>

                    <div className="list-group">
                        {
                            this.state.logs.map(val => {
                                return <a key={val}
                                          href={`/logs/${this.getPathWithoutExt(val)}`}
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
