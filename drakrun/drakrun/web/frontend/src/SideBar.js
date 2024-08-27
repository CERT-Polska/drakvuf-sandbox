import React, { useState } from "react";
import Box from "@mui/material/Box";
import Tab from "@mui/material/Tab";
import TabContext from "@mui/lab/TabContext";
import TabList from "@mui/lab/TabList";
import TabPanel from "@mui/lab/TabPanel";
import "./behavioralGraph.css";

function getTTPs(report, selectedProcessID) {
  let ttps_list = new Set();
  if (selectedProcessID) {
    // Get a list of TTPs for only the selected process
    report["processes"][selectedProcessID]["ttps"].forEach((ttp) => {
      ttp["att&ck"].map((attck_name) => ttps_list.add(attck_name));
    });
  } else {
    // Get a list of all the TTPs found in the report
    for (let process of Object.values(report["processes"])) {
      process["ttps"].forEach((ttp) => {
        ttp["att&ck"].map((attck_name) => ttps_list.add(attck_name));
      });
    }
  }

  return [...ttps_list];
}

function getFiles(report, selectedProcessID) {
  let files_list = new Set();
  if (selectedProcessID) {
    // Get a list of TTPs for only the selected process
    report["processes"][selectedProcessID]["files"].forEach((file) => {
      files_list.add(file);
    });
  } else {
    // Get a list of all the TTPs found in the report
    for (let process of Object.values(report["processes"])) {
      process["files"].forEach((file) => {
        files_list.add(file);
      });
    }
  }
  return [...files_list];
}

function getRegistry(report, selectedProcessID) {
  let regkeys_list = new Set();
  if (selectedProcessID) {
    // Get a list of TTPs for only the selected process
    report["processes"][selectedProcessID]["registry_keys"].forEach(
      (regkey) => {
        regkeys_list.add(regkey);
      }
    );
  } else {
    // Get a list of all the TTPs found in the report
    for (let process of Object.values(report["processes"])) {
      process["registry_keys"].forEach((regkey) => {
        regkeys_list.add(regkey);
      });
    }
  }
  return [...regkeys_list];
}

export default function LabTabs({
  report,
  selectedProcess,
  onSelectTTP,
  onSelectFile,
  onSelectRegistry,
}) {
  const ttpsList = getTTPs(report, selectedProcess).map((ttp) => (
    <>
      <tr
        onClick={() => {
          onSelectTTP(ttp);
        }}
      >
        <td>{ttp}</td>
      </tr>
      <hr style={{ marginTop: "0px", marginBottom: "0px" }}></hr>
    </>
  ));
  const filesList = getFiles(report).map((file) => (
    <>
      <tr
        onClick={() => {
          onSelectFile(file);
        }}
      >
        <td>{file}</td>
      </tr>
      <hr style={{ marginTop: "0px", marginBottom: "0px" }}></hr>
    </>
  ));
  const registryList = getRegistry(report).map((registry) => (
    <>
      <tr
        onClick={() => {
          onSelectRegistry(registry);
        }}
      >
        <td>{registry}</td>
      </tr>
      <hr style={{ marginTop: "0px", marginBottom: "0px" }}></hr>
    </>
  ));
  const [value, setValue] = useState("1");
  const handleChange = (event, newValue) => {
    setValue(newValue);
  };

  return (
    <Box sx={{ typography: "body1" }}>
      <TabContext value={value}>
        <Box
          sx={{
            borderBottom: 3,
            borderColor: "divider",
            backgroundColor: "#343538",
          }}
        >
          <TabList
            onChange={handleChange}
            variant="fullWidth"
            sx={{
              ".Mui-textColorInherit": {
                color: `orange`,
              },
            }}
          >
            <Tab label="TTPs" value="1" />
            <Tab label="Files" value="2" />
            <Tab label="Registry" value="3" />
          </TabList>
        </Box>
        <TabPanel
          value="1"
          style={{
            overflowY: "scroll",
            minHeight: "95.5vh",
            maxHeight: "95.5vh",
            margin: 0,
            padding: 0,
            backgroundColor: "black",
          }}
        >
          <table style={{ width: "100%" }}>{ttpsList}</table>
        </TabPanel>
        <TabPanel
          value="2"
          style={{
            overflowY: "scroll",
            minHeight: "95.5vh",
            maxHeight: "95.5vh",
            margin: 0,
            padding: 0,
            backgroundColor: "black",
          }}
        >
          <table style={{ width: "100%" }}>{filesList}</table>
        </TabPanel>
        <TabPanel
          value="3"
          style={{
            overflowY: "scroll",
            minHeight: "95.5vh",
            maxHeight: "95.5vh",
            margin: 0,
            padding: 0,
            backgroundColor: "black",
          }}
        >
          <table style={{ width: "100%" }}>{registryList}</table>
        </TabPanel>
      </TabContext>
    </Box>
  );
}
