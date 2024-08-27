import React, { useState } from "react";
import Button from "@mui/material/Button";
import ProcessTree from "./Tree.js";
import LabTabs from "./SideBar.js";
import api from "./api";
import "./index.css";

function sortByProcess(jsonLinesDict, key) {
  let sortedDict = {};
  let pKey = "";
  for (let entry of jsonLinesDict) {
    pKey = entry["PID"] + "_" + entry["PPID"];
    if (!(pKey in sortedDict)) {
      sortedDict[pKey] = new Set();
    }
    sortedDict[pKey].add(entry[key]);
  }
  return sortedDict;
}

function addToReport(report, dict, key) {
  for (let k of Object.keys(report["processes"])) {
    // Add an empty entry to all processes in case some do not manipulate files/registry keys
    report["processes"][k][key] = [];
  }
  for (let processKey of Object.keys(dict)) {
    report["processes"][processKey][key] = [...dict[processKey]];
  }
}

export function InteractiveGraph(analysisID) {
  const [process, setProcess] = useState(false);
  const [ttp, setTtp] = useState(false);
  const [file, setFile] = useState(false);
  const [registry, setRegistry] = useState(false);
  const clearAllFilters = () => {
    setProcess(false);
    setTtp(false);
    setFile(false);
    setRegistry(false);
  };

  // Fetch necessary files: `report.json`, `filetracer.log`, and `regmon.log`
  var report = await api.getReport(analysisID);
  var files = await api.getLog(analysisID, "filetracer.log");
  var regkeys = await api.getLog(analysisID, "regmon.log");

  // Get a dictionary from JSON lines for `filetracer.log` and `regmon.log`
  files = files.request.response.split("\n").map((line) => {
    try {
      return JSON.parse(line);
    } catch (e) {
      console.log("Parsing JSON entry failed");
    }
    return null;
  });

  regkeys = regkeys.request.response.split("\n").map((line) => {
    try {
      return JSON.parse(line);
    } catch (e) {
      console.log("Parsing JSON entry failed");
    }
    return null;
  });

  // Sort `filetracer.log` and `regmon.log` by entry, then append them to the respective process in the report.
  var filesPerProcess = sortByProcess(files, "FileName");
  addToReport(report, filesPerProcess, "files");
  var regkeyPerProcess = sortByProcess(regkeys, "Key");
  addToReport(report, regkeyPerProcess, "registry_keys");

  return (
    <>
      <ProcessTree
        report={report}
        selectedTTP={ttp}
        selectedFile={file}
        selectedRegistry={registry}
        onSelectProcess={(process_id) => setProcess(process_id)}
      />
      <div className="rowC">
        <LabTabs
          report={report}
          selectedProcess={process}
          onSelectTTP={(ttp_name) => {
            clearAllFilters();
            setTtp(ttp_name);
          }}
          onSelectFile={(filename) => {
            clearAllFilters();
            setFile(filename);
          }}
          onSelectRegistry={(regkey) => {
            clearAllFilters();
            setRegistry(regkey);
          }}
        />
      </div>
      <Button
        onClick={() => clearAllFilters()}
        style={{
          position: "absolute",
          left: 13,
          bottom: 13,
          fontSize: 15,
          maxWidth: "100px",
        }}
        variant="contained"
      >
        Clear Selections
      </Button>
    </>
  );
}
