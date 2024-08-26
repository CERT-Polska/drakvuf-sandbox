import React, { useState } from 'react';
import Box from '@mui/material/Box';
import Tab from '@mui/material/Tab';
import TabContext from '@mui/lab/TabContext';
import TabList from '@mui/lab/TabList';
import TabPanel from '@mui/lab/TabPanel';

function getTTPs(report, selectedProcessID) {
  let ttps_list = new Set();
  if(selectedProcessID){
    // Get a list of TTPs for only the selected process
    report["processes"][selectedProcessID]["ttps"].forEach((ttp) => {ttps_list.add(ttp["att&ck"])})
  } else {
    
    // Get a list of all the TTPs found in the report
    for(let process of Object.values(report["processes"])){
      process["ttps"].forEach((ttp) => {ttps_list.add(ttp["att&ck"])})
    }
  }
  return [...ttps_list];
}

function getFiles(report, selectedProcessID) {
  let ttps_list = new Set();
  if(selectedProcessID){
    // Get a list of TTPs for only the selected process
    report["processes"][selectedProcessID]["ttps"].forEach((ttp) => {ttps_list.add(ttp["att&ck"])})
  } else {
    
    // Get a list of all the TTPs found in the report
    for(let process of Object.values(report["processes"])){
      process["ttps"].forEach((ttp) => {ttps_list.add(ttp["att&ck"])})
    }
  }
  return [...ttps_list];
}

function getRegistry(report, selectedProcessID) {
  let ttps_list = new Set();
  if(selectedProcessID){
    // Get a list of TTPs for only the selected process
    report["processes"][selectedProcessID]["ttps"].forEach((ttp) => {ttps_list.add(ttp["att&ck"])})
  } else {
    
    // Get a list of all the TTPs found in the report
    for(let process of Object.values(report["processes"])){
      process["ttps"].forEach((ttp) => {ttps_list.add(ttp["att&ck"])})
    }
  }
  return [...ttps_list];
}

export default function LabTabs({report, selectedProcess, onSelectTTP, onSelectFile, onSelectRegistry}) {
  const ttpsList = getTTPs(report, selectedProcess).map((ttp) => <><tr onClick={() => {onSelectTTP(...ttp)}}  style={{fontSize: 21}}>{ttp}</tr><hr style={{marginTop: '13px', marginBottom: '13px'}}></hr></>);
  const filesList = getFiles(report).map((file) => <><tr onClick={() => onSelectFile(file)} style={{fontSize: 21}}>{file}</tr><hr style={{marginTop: '13px', marginBottom: '13px'}}></hr></>);
  const registryList = getRegistry(report).map((registry) => <><tr onClick={() => onSelectRegistry(registry)} style={{fontSize: 21}}>{registry}</tr><hr style={{marginTop: '13px', marginBottom: '13px'}}></hr></>);
  const [value, setValue] = useState('1');
  const handleChange = (event, newValue) => {
    setValue(newValue);
  };

  return (
    <Box sx={{ typography: 'body1' }} >
      <TabContext value={value} >
        <Box sx={{ borderBottom: 3, borderColor: 'divider' , backgroundColor: '#343538',}}>
          <TabList onChange={handleChange} variant="fullWidth" >
              <Tab label="TTPs" value="1" />
              <Tab label="Files" value="2" />
              <Tab label="Registry" value="3" />
          </TabList>
        </Box>
        <TabPanel value="1" style={{overflowY:"scroll", maxHeight:"90vh"}}>
          {ttpsList}
        </TabPanel>
        <TabPanel value="2" style={{overflowY:"scroll", maxHeight:"90vh"}}>
          {filesList}
        </TabPanel>
        <TabPanel value="3" style={{overflowY:"scroll", maxHeight:"90vh"}}>
          {registryList}
        </TabPanel>
      </TabContext>
    </Box>
  );
}
