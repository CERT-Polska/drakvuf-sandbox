function TreeNode({processNode, selectedId, level = 0}) {

}

function ProcessTree() {
  return (
      <ul>
        <li>explorer.exe</li>
      </ul>
  )
}

function AnalysisMetadataTable() {
    return (
      <table className="datatable-table">
          <tbody>
            <tr>
              <th>SHA256</th>
              <td>01ecee7ec00cc971d6e13498b2225f8b591fc7ec02a21db3a1dc868f5c934396</td>
            </tr>
            <tr>
              <th>Type</th>
              <td>PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows</td>
            </tr>
            <tr>
              <th>Start command</th>
              <td>C:\Users\janusz\Desktop\PO_of_W11741147.exe</td>
            </tr>
            <tr>
              <th>Started at</th>
              <td>2025-04-17 12:05:56</td>
            </tr>
            <tr>
              <th>Finished at</th>
              <td>2025-04-17 12:11:18</td>
            </tr>
            <tr>
              <th>Plugins</th>
              <td></td>
            </tr>
            <tr>
              <th>VM ID</th>
              <td></td>
            </tr>
          </tbody>
      </table>
    );
}

function AnalysisTabs() {
  return (
      <>
      <nav>
        <div className="nav nav-tabs" id="nav-tab" role="tablist">
          <button className="nav-link active" data-bs-toggle="tab" data-bs-target="#nav-home"
                  type="button" role="tab" aria-controls="nav-home" aria-selected="true">
            Summary
          </button>
          <button className="nav-link" data-bs-toggle="tab" data-bs-target="#nav-profile"
                  type="button" role="tab" aria-controls="nav-profile" aria-selected="false">
            DRAKVUF logs
          </button>
          <button className="nav-link" data-bs-toggle="tab" data-bs-target="#nav-contact"
                  type="button" role="tab" aria-controls="nav-contact" aria-selected="false">
            Process logs
          </button>
        </div>
      </nav>
      <div className="tab-content" id="nav-tabContent">
        <div className="tab-pane fade show active" role="tabpanel">...</div>
        <div className="tab-pane fade" role="tabpanel">...</div>
        <div className="tab-pane fade" role="tabpanel">...</div>
      </div>
      </>
)
}

function AnalysisStatus(props) {
  return (
    <div className="card">
      <div className="card-body">
        <div className="pb-2">
          Fetching analysis data...
        </div>
        <div className="progress">
          <div className="progress-bar progress-bar-striped progress-bar-animated" role="progressbar"
               aria-valuenow="100" aria-valuemin="0" aria-valuemax="100" style={{"width": "100%"}}></div>
        </div>
      </div>
    </div>
  )
}


export default function AnalysisView(props) {
  return (
      <div className="container-fluid px-4">
        <h1 className="m-4 h4">Analysis report</h1>
        <div className="row">
          <div className="col-xl-6">
            <AnalysisStatus/>
          </div>
          <div className="col-xl-6">
            <div className="card">
              <div className="card-body">
                <div className="fw-bold pb-2">Metadata</div>
                <AnalysisMetadataTable/>
              </div>
            </div>
          </div>
        </div>
        <div className="row py-4">
          <div className="col">
            <div className="card">
              <div className="card-body">
                <AnalysisTabs/>
              </div>
            </div>
          </div>
        </div>
      </div>
  )
}
