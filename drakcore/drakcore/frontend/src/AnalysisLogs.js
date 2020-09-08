import React, { useState, useEffect } from "react";
import OptionPicker from "./OptionPicker";
import { Tabs, TabItem } from "./Tabs";
import LogBrowser from "./LogBrowser";
import api from "./api";
import { Redirect } from "react-router-dom";

function isServiceLog(name) {
  const SERVICE_LOGS = ["drakrun.log", "drak-postprocess.log"];
  return SERVICE_LOGS.some((s) => name.includes(s));
}

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

function DownloadButton({ filename, href, children }) {
  return (
    <a download={filename} href={href} className="btn btn-primary">
      {children}
    </a>
  );
}

function getLogName(logPath) {
  return logPath.split("/").slice(-1)[0];
}

async function getLogChunk(analysisID, log, from, to) {
  const chunks = await api.getLogRange(analysisID, log.split(".")[0], from, to);

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

function useLogIndex(analysisID, log) {
  const [index, setIndex] = useState(null);

  useEffect(() => {
    if (log === null) {
      return;
    }
    setIndex(null);
    api
      .logIndex(analysisID, log.split(".")[0])
      .then((index) => {
        if (index) {
          setIndex(index.data);
        }
      })
      .catch(() => {
        setIndex({
          num_lines: 0,
          markers: [{ line: 0, offset: 0 }],
        });
      });
  }, [analysisID, log]);

  return index;
}

function useLogList(analysisID) {
  const [logList, setLogList] = useState(null);
  // Download log list during initialization
  useEffect(() => {
    api.listLogs(analysisID).then((logs) => {
      if (logs) {
        setLogList(logs.data.map(getLogName));
      }
    });
  }, [analysisID]);

  return logList;
}

function LogView({ analysisID, log }) {
  const index = useLogIndex(analysisID, log);

  if (log === null || index === null) {
    return "Loading...";
  }

  const entryComponent = isServiceLog(log) ? ServiceRow : DrakvufRow;
  const getData = (from, to) => {
    return getLogChunk(analysisID, log, from, to);
  };

  return (
    <LogBrowser index={index} queryData={getData}>
      {entryComponent}
    </LogBrowser>
  );
}

function LogViewControl({ analysisID, setLog, displayedLog }) {
  const logList = useLogList(analysisID);

  const logGroups = {
    services: logList ? logList.filter(isServiceLog) : [],
    drakvuf: logList ? logList.filter((log) => !isServiceLog(log)) : [],
  };

  let displayedGroup;
  if (logGroups.services.includes(displayedLog)) {
    displayedGroup = "services";
  } else {
    displayedGroup = "drakvuf";
  }

  const intoOption = (obj) => {
    const log_name = getLogName(obj);
    return { key: log_name, value: log_name };
  };

  const setTab = (label) => {
    setLog(logGroups[label][0]);
  };

  const tabs = (
    <Tabs selected={displayedGroup} onChange={setTab}>
      <TabItem label={"drakvuf"} value={"DRAKVUF"} />
      <TabItem label={"services"} value={"Services"} />
    </Tabs>
  );

  return (
    <>
      {tabs}
      <div className="row mb-2">
        <div className="col">
          <OptionPicker
            selected={displayedLog}
            data={logGroups[displayedGroup].map(intoOption)}
            onChange={setLog}
          />
        </div>
        <DownloadButton
          filename={displayedLog}
          href={"/log/" + analysisID + "/" + displayedLog}
        >
          Download log
        </DownloadButton>
      </div>
    </>
  );
}

function AnalysisLogs(props) {
  const analysisID = props.match.params.analysis;
  const [log, setLog] = useState(props.match.params.log || null);

  // Ensure the URL is up to date
  if (log && props.match.params.log !== log) {
    return <Redirect to={`/analysis/${analysisID}/logs/${log}`} />;
  }

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
          <LogViewControl
            analysisID={analysisID}
            displayedLog={log}
            setLog={setLog}
          />
          <div style={{ flex: 1 }}>
            <LogView analysisID={analysisID} log={log} />
          </div>
        </div>
      </div>
    </div>
  );
}

export default AnalysisLogs;
