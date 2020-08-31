import React from "react";
import { Component } from "react";
import { FixedSizeList as List } from "react-window";
import OptionPicker from "./OptionPicker";
import "./App.css";
import api from "./api";

class AnalysisApicall extends Component {
  constructor(props) {
    super(props);

    this.analysis_id = this.props.match.params.analysis;

    this.state = {
      calls: null,
      processList: [],
      filter: '',
      filteredResults: [],
    };

    this.pidChanged = this.pidChanged.bind(this);
    this.filterChanged = this.filterChanged.bind(this);
    this.computeFiltered = this.computeFiltered.bind(this);
  }

  async pidChanged(new_pid) {
    try {
      this.setState({ calls: null });
      const res = await api.getApiCalls(this.analysis_id, new_pid);
      const calls = res.data.split("\n").map(JSON.parse);
      this.setState({ calls });
      this.computeFiltered(this.state.filter);
    } catch (e) {
      this.setState({ calls: [] });
    }
  }

  computeFiltered(filter) {
    if (filter === '') {
      this.setState({ filteredResults: this.state.calls });
      return;
    }
    try {
      let regex = new RegExp(filter, 'gi');
      this.setState({
        filteredResults: this.state.calls.filter((elem) =>
          regex.test(elem.method)
        ),
      });
    } catch  { }
  }

  filterChanged(event) {
    const newFilter = event.target.value;
    this.setState({filter: newFilter});
    this.computeFiltered(newFilter);
  }

  async componentDidMount() {
    const analysis = this.props.match.params.analysis;
    const process_tree = await api.getProcessTree(analysis);

    function treeFlatten(process_tree) {
      let result = [];

      process_tree.forEach((proc) => {
        result.push({ key: proc.pid, value: `${proc.pid} – ${proc.procname || "unnamed process"}` });
        result.push(...treeFlatten(proc.children));
      });

      result.sort((a, b) => a.key - b.key);

      return result;
    }

    if (process_tree) {
      this.setState({ processList: treeFlatten(process_tree.data) });

      const pid = parseInt(this.props.match.params.pid);
      this.pidChanged(pid);
    }
  }

  render() {
    const url_pid = parseInt(this.props.match.params.pid);

    let content;
    if (this.state.calls === null) {
      content = (
        <div
          className="alert alert-primary d-flex align-items-center"
          role="alert"
        >
          Loading....
          <div
            className="spinner-border ml-auto"
            role="status"
            aria-hidden="true"
          ></div>
        </div>
      );
    } else if (this.state.calls.length === 0) {
      content = (
        <div className="alert alert-primary" role="alert">
          No API calls found for this process
        </div>
      );
    } else {
      // let tableContent = this.state.calls.map((entry, i) => (
      //   <tr key={i}>
      //     <td>{entry.timestamp}</td>
      //     <td>
      //       <code>{entry.method}</code>
      //     </td>
      //     <td>
      //       {entry.arguments.map((arg, i) => (
      //         <div key={i} className="badge-outline-primary badge mr-1">
      //           {arg}
      //         </div>
      //       ))}
      //     </td>
      //   </tr>
      // ));

      const Row = ({ data, index, style }) => {
        const entry = data[index];
        const args = entry.arguments.join(", ");
        return (
          <div style={style} className="d-flex flex-row align-content-stretch">
            <div className="p-1 d-none d-md-block">{entry.timestamp}</div>
            <div className="p-1" style={{overflow: "hidden", wordBreak:"break-all"}}>
              <code>
                {entry.method}({args}) = ?
              </code>
            </div>
          </div>
        );
      };

      let tableContent = (
        <List
          itemData={this.state.filteredResults}
          height={600}
          itemCount={this.state.filteredResults ? this.state.filteredResults.length : 0}
          itemSize={28}
        >
          {Row}
        </List>
      );

      content = tableContent;

      // content = (
      //   <table className="table table-centered apicallTable">
      //     <thead>
      //       <tr>
      //         <th>Timestamp</th>
      //         <th>Method</th>
      //         <th>Arguments</th>
      //       </tr>
      //     </thead>
      //     <tbody>{tableContent}</tbody>
      //   </table>
      // );
    }

    return (
      <div className="App container-fluid">
        <div className="page-title-box">
          <h4 className="page-title">API calls</h4>
        </div>

        <div className="card tilebox-one">
          <div className="card-body">
            <div className="row mb-2">
              <div className="col-9">
                <OptionPicker
                  defaultSelection={url_pid}
                  data={this.state.processList}
                  onChange={(pid) => this.pidChanged(parseInt(pid))}
                />
              </div>
              <input
                type="text"
                className="form-control col-3"
                placeholder="Search API calls..."
                value={this.state.filter}
                onChange={this.filterChanged}
              />
            </div>
            {content}
          </div>
        </div>
      </div>
    );
  }
}

export default AnalysisApicall;
