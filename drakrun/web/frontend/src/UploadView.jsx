import { PluginPicker } from "./PluginPicker.jsx";
import { useNavigate } from "react-router-dom";
import { useCallback, useRef, useState } from "react";
import { uploadSample } from "./api.js";

export default function UploadView(props) {
    const [valid, setValid] = useState(true);
    const [submitted, setSubmitted] = useState(false);
    const [filenameWarning, setFilenameWarning] = useState(undefined);
    const [pluginsWarning, setPluginsWarning] = useState(undefined);
    const [error, setError] = useState();
    const [analysisTime, setAnalysisTime] = useState(10);
    const navigate = useNavigate();

    const validatePlugins = useCallback((plugins) => {
        if (plugins.length === 0) {
            setPluginsWarning("You need to pick at least one plugin");
            setValid(false);
        } else {
            setPluginsWarning(undefined);
            setValid(true);
        }
    }, []);

    const checkName = useCallback((ev) => {
        const filename = ev.target.name;
        if (filename) {
            if (!filename.includes(".")) {
                setFilenameWarning(
                    "File doesn't have proper extension. " +
                        "Consider providing 'Target file name' for correct execution.",
                );
                return;
            }
        }
        setFilenameWarning(undefined);
    }, []);

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
                    no_internet: form.get("no_internet"),
                    no_screenshots: form.get("no_screenshots"),
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
                        onChange={checkName}
                        required
                    />
                    {filenameWarning ? (
                        <div className="text-danger small">
                            {filenameWarning}
                        </div>
                    ) : (
                        []
                    )}
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
                    <PluginPicker name="plugins" onChange={validatePlugins} />
                    {pluginsWarning ? (
                        <div className="text-danger small">
                            {pluginsWarning}
                        </div>
                    ) : (
                        []
                    )}
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
                <div className="mb-3 form-check">
                    <input
                        className="form-check-input"
                        id="no-internet"
                        type="checkbox"
                        name="no_internet"
                    />
                    <label className="form-check-label" htmlFor="no-internet">
                        Disable Internet access
                    </label>
                </div>
                <div className="mb-3 form-check">
                    <input
                        className="form-check-input"
                        id="no-screenshots"
                        type="checkbox"
                        name="no_screenshots"
                    />
                    <label
                        className="form-check-label"
                        htmlFor="no-screenshots"
                    >
                        Disable screenshots
                    </label>
                </div>
                <div className="mb-3">
                    <button
                        className="btn btn-primary"
                        disabled={submitted || !valid}
                        type="submit"
                    >
                        Submit
                    </button>
                </div>
            </form>
        </div>
    );
}
