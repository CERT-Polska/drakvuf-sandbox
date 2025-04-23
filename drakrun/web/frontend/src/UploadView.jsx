import { PluginPicker } from "./PluginPicker.jsx";
import { useNavigate } from "react-router-dom";
import { useCallback, useState } from "react";
import { uploadSample } from "./api.js";

export default function UploadView(props) {
    const [submitted, setSubmitted] = useState(false);
    const [error, setError] = useState();
    const [analysisTime, setAnalysisTime] = useState(10);
    const navigate = useNavigate();

    const submitForm = useCallback(
        async (ev) => {
            ev.preventDefault();
            setSubmitted(true);
            const form = new FormData(ev.target);
            try {
                const jobData = await uploadSample({
                    file: form.get("file"),
                    timeout: form.get("timeout") * 60,
                    plugins: form.getAll("plugins"),
                    file_name: form.get("file_name"),
                    start_command: form.get("start_command"),
                });
                const jobId = jobData["task_uid"];
                navigate(`/analysis/${jobId}`);
            } catch (e) {
                setError(e);
                setSubmitted(false);
                console.error(e);
            }
        },
        [navigate],
    );
    return (
        <div className="container-fluid px-4">
            <h1 className="m-4 h4">Upload sample</h1>
            {error ? <div className="text-danger">Error: {error}</div> : []}
            <form onSubmit={submitForm}>
                <div className="mb-3">
                    <label htmlFor="formFile" className="form-label">
                        Sample file
                    </label>
                    <input
                        className="form-control"
                        type="file"
                        id="formFile"
                        name="file"
                        required
                    />
                </div>
                <div className="mb-3">
                    <label htmlFor="form-timeout" className="form-label">
                        Analysis time: {analysisTime} minute
                        {analysisTime > 1 ? "s" : ""}
                    </label>
                    <input
                        type="range"
                        className="form-range"
                        min="1"
                        max="15"
                        value={analysisTime}
                        onChange={(ev) => setAnalysisTime(+ev.target.value)}
                        id="form-timeout"
                        name="timeout"
                    />
                </div>
                <div className="mb-3">
                    <label className="form-label">Plugins</label>
                    <PluginPicker name="plugins" />
                </div>
                <div className="mb-3">
                    <label htmlFor="target-file-name" className="form-label">
                        Target file name
                    </label>
                    <input
                        type="text"
                        className="form-control"
                        id="target-file-name"
                        name="file_name"
                        placeholder="(pick automatically)"
                    />
                </div>
                <div className="mb-3">
                    <label
                        htmlFor="custom-start-command"
                        className="form-label"
                    >
                        Start command
                    </label>
                    <input
                        type="text"
                        className="form-control"
                        id="custom-start-command"
                        name="start_command"
                        placeholder="(pick automatically)"
                    />
                </div>
                <div className="mb-3">
                    <button
                        className="btn btn-primary"
                        disabled={submitted}
                        type="submit"
                    >
                        Submit
                    </button>
                </div>
            </form>
        </div>
    );
}
