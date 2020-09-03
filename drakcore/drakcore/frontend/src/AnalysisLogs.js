import React from "react";
import OptionPicker from "./OptionPicker";
import { Tabs, TabItem } from "./Tabs";
import LogBrowser from "./LogBrowser";
import api from "./api";

const SERVICE_LOGS = ["drakrun.log", "drak-postprocess.log"];

const DrakvufRow = ({ entry, style }) => {
  let content;
  let displayed = { ...entry };
  if (entry === undefined) {
    content = "Loading...";
  } else {
    content = (
      <code style={{ whiteSpace: "nowrap" }}>{JSON.stringify(displayed)}</code>
    );
  }

  return (
    <div style={style} className="d-flex flex-row align-content-stretch">
      <div className="p-1">{content}</div>
    </div>
  );
};

const ServiceRow = ({ entry, index, style }) => {
  if (entry === undefined) {
    return "Loading...";
  }
  return (
    <div style={style} className="d-flex flex-row align-content-stretch">
      <div className="p-1">
        <div>
          <code style={{ whiteSpace: "nowrap" }}>{entry.message}</code>
        </div>
      </div>
    </div>
  );
};

class AnalysisLogs extends React.Component {
  constructor(props) {
    super(props);
    this.analysisID = this.props.match.params.analysis;

    this.state = {
      currentLog: null,
      currentTab: "drakvuf",
      logList: [],
      index: null,
    };

    this.selectionChanged = this.selectionChanged.bind(this);
    this.getLogChunk = this.getLogChunk.bind(this);
    this.setTab = this.setTab.bind(this);
  }

  setTab(tab) {
    this.setState({ currentTab: tab });
  }

  async getLogChunk(from, to) {
    const chunks = await api.getLogRange(
      this.analysisID,
      this.state.currentLog.split(".")[0],
      from,
      to
    );
    if (chunks) {
      return chunks.request.response.split("\n").map((line) => {
        try {
          return JSON.parse(line);
        } catch (e) {
          console.log("Parsing JSON entry failed");
        }
        return null;
      });
    }
    return null;
  }

  async componentDidMount() {
    const logs = await api.listLogs(this.analysisID);
    if (logs) {
      this.setState({
        logList: logs.data,
      });
    }
    const defaltSelection = logs.data[0].split("/")[1];
    await this.selectionChanged(defaltSelection);
  }

  async selectionChanged(newSelection) {
    try {
      const index = await api.logIndex(
        this.analysisID,
        newSelection.split(".")[0]
      );
      this.setState({ index: index.data, currentLog: newSelection });
    } catch {
      this.setState({ index: null, currentLog: newSelection });
    }
  }

  render() {
    const handleMissingIndex = (index) => {
      if (index !== null) {
        return index;
      }
      return {
        num_lines: 0,
        markers: [{ line: 0, offset: 0 }],
      };
    };

    const isServiceLog = (name) =>
      SERVICE_LOGS.some((s) => {
        return name.includes(s);
      });

    const intoOption = (obj) => {
      const log_name = obj.split("/")[1];
      return { key: log_name, value: log_name };
    };

    const logClassPredicate = {
      services: isServiceLog,
      drakvuf: (log_name) => !isServiceLog(log_name),
    };

    const logClass = logClassPredicate[this.state.currentTab] || ((s) => true);

    const entryComponent = {
      services: ServiceRow,
      drakvuf: DrakvufRow,
    };

    if (this.state.currentLog === null || this.state.currentTab === null)
      return "Loading..";

    const content = (
      <>
        <Tabs onChange={this.setTab}>
          <TabItem label={"drakvuf"} value={"DRAKVUF"} />
          <TabItem label={"services"} value={"Services"} />
        </Tabs>
        <div className="row mb-2">
          <div className="col">
            <OptionPicker
              data={this.state.logList.filter(logClass).map(intoOption)}
              onChange={this.selectionChanged}
            />
          </div>
          <a
            download={this.state.currentLog}
            href={"/log/" + this.analysisID + "/" + this.state.currentLog}
            className="btn btn-primary"
          >
            Download log
          </a>
        </div>

        <div style={{ flex: 1 }}>
          <LogBrowser
            index={handleMissingIndex(this.state.index)}
            queryData={this.getLogChunk}
          >
            {entryComponent[this.state.currentTab]}
          </LogBrowser>
        </div>
      </>
    );

    return (
      <div
        className="App container-fluid d-flex"
        style={{ flex: 1, flexFlow: "column" }}
      >
        <div className="page-title-box">
          <h4 className="page-title">Analysis logs</h4>
        </div>

        <div className="card tilebox-one" style={{ flex: 1 }}>
          <div className="card-body d-flex" style={{ flexFlow: "column" }}>
            {this.state.currentLog !== null ? content : ""}
          </div>
        </div>
      </div>
    );
  }
}

export default AnalysisLogs;
