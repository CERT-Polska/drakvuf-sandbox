import React, { useState, useEffect } from "react";
import OptionPicker from "./OptionPicker";
import { Tabs, TabItem } from "./Tabs";
import LogBrowser from "./LogBrowser";
import api from "./api";

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

function LogWithIndex({ analysisID, log }) {
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

function LogViewControl({ analysisID, setLog }) {
  const [tab, setTab] = useState("drakvuf");
  const [log, setCurrentLog] = useState(null);
  const [logList, setLogList] = useState(null);

  const intoOption = (obj) => {
    const log_name = getLogName(obj);
    return { key: log_name, value: log_name };
  };

  // Download log list during initialization
  useEffect(() => {
    api.listLogs(analysisID).then((logs) => {
      if (logs) {
        setLogList(logs.data);

        const firstLog = getLogName(logs.data[0]);
        setLog(firstLog);
      }
    });
  }, [setLog, analysisID]);

  useEffect(() => {
    setLog(log);
  }, [setLog, log]);

  if (logList === null) {
    return "";
  }

  const logClassPredicate = {
    services: isServiceLog,
    drakvuf: (log_name) => !isServiceLog(log_name),
  };

  const logClass = logClassPredicate[tab] || ((s) => true);

  const tabs = (
    <Tabs selected={tab} onChange={setTab}>
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
            data={logList.filter(logClass).map(intoOption)}
            onChange={setCurrentLog}
          />
        </div>
        <DownloadButton filename={log} href={"/log/" + analysisID + "/" + log}>
          Download log
        </DownloadButton>
      </div>
    </>
  );
}

function AnalysisLogs(props) {
  const analysisID = props.match.params.analysis;
  const [log, setLog] = useState(null);

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
          <LogViewControl analysisID={analysisID} setLog={setLog} />
          <div style={{ flex: 1 }}>
            <LogWithIndex analysisID={analysisID} log={log} />
          </div>
        </div>
      </div>
    </div>
  );
}

export default AnalysisLogs;
