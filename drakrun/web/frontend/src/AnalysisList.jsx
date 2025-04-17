import {Link} from "react-router-dom";

export default function AnalysisList(props) {
  return (
    <div className="container-fluid px-4">
      <h1 className="m-4 h4">Analyses</h1>
      <div className="datatable-container">
        <table className="datatable-table">
          <thead>
            <tr>
              <th>Analysis ID</th>
              <th>Sample info</th>
              <th>Started</th>
              <th>Finished</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>
                <div className="badge bg-info me-2 p-2">pending</div>
                <Link to="/analysis/697204f4-1585-4f50-b58a-c4742cf03d6a">697204f4-1585-4f50-b58a-c4742cf03d6a</Link>
              </td>
              <td>
                <div className="d-flex flex-row flex-wrap font-monospace">
                  <div className="fw-bold pe-2">SHA256:</div>
                  <div>
                    01ecee7ec00cc971d6e13498b2225f8b591fc7ec02a21db3a1dc868f5c934396
                  </div>
                </div>
                <div className="d-flex flex-row flex-wrap font-monospace">
                  <div className="fw-bold pe-2">Command:</div>
                  <div>C:\Users\janusz\Desktop\updater.exe</div>
                </div>
                <div className="d-flex flex-row flex-wrap">
                  <div className="fw-bold pe-2">Type:</div>
                  <div>
                    MS-DOS executable PE32 executable (GUI) Intel 80386
                    (stripped to external PDB), for MS Windows, MZ for MS-DOS
                  </div>
                </div>
              </td>
              <td>2025-04-17 08:43:39.568Z</td>
              <td>2025-04-17 08:49:01.344Z</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}
