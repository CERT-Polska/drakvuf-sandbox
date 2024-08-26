import React, { useState } from "react";
import Button from '@mui/material/Button';
import ProcessTree from "./ProcessTree.js";
import ReactDOM from "react-dom";
import LabTabs from "./Tabs.js";
import './index.css';

var report = require('./report.json');

function App() {
  const [process, setProcess] = useState(false);
  const [TTP, setTTP] = useState(false);
  const [file, setFile] = useState(false);
  const [registry, setRegistry] = useState(false);

  return (
    <>
      <ProcessTree
        report={report}
        selectedTTP={TTP}
        selectedFile={file}
        selectedRegistry={registry}
        onSelectProcess={(process_id) => setProcess(process_id)}
      />
      <div className="rowC" >
        <LabTabs
          report={report}
          selectedProcess={process}
          onSelectTTP={(ttp_name) => {setTTP(ttp_name)}}
          onSelectFile={(filename) => setFile(filename)}
          onSelectRegistry={(regkey) => setRegistry(regkey)}
        />
      </div>
      <Button onClick={(() => {setProcess(false); setTTP(false); setFile(false); setRegistry(false);})} style={{position: 'absolute', left: 10, bottom: 10, fontSize: 15, maxWidth: '100px'}} variant="contained">Clear Selections</Button>
    </>
  );
  }
  const root = ReactDOM.createRoot(document.getElementById('root'));
  root.render(
  <App />
  );