import { PluginPicker } from "./PluginPicker.jsx";
import { useNavigate } from "react-router-dom";
import { useCallback, useRef, useState } from "react";
import { uploadSample } from "./api.js";

function FormError({ errors, field }) {
    const error = errors[field];
    if (error) {
        return <div className="text-danger small">{error}</div>;
    }
    return [];
}

export default function UploadView() {
    const [valid, setValid] = useState(true);
    const [submitted, setSubmitted] = useState(false);
    const formRef = useRef(undefined);
    const [formErrors, setFormErrors] = useState({});
    const [error, setError] = useState();
    const [analysisTime, setAnalysisTime] = useState(10);
    const [extractArchive, setExtractArchive] = useState(false);
    const navigate = useNavigate();

    const validateForm = useCallback(() => {
        const form = new FormData(formRef.current);
        const filename = form.get("file").name;
        const archiveEntryPath = form.get("archive_entry_path");
        const targetFileName = form.get("file_name");
        const targetStartCommand = form.get("start_command");
        const extractArchive = form.get("extract_archive");

        let isValid = true;
        let formErrors = {};

        if (form.getAll("plugins").length === 0) {
            formErrors["plugins"] = "You need to pick at least one plugin";
            isValid = false;
        }

        if (filename && !filename.includes(".")) {
            formErrors["form-file"] =
                "File doesn't have proper extension. " +
                "Consider providing 'Target file name' for correct execution.";
        }

        if (extractArchive && !archiveEntryPath && !targetStartCommand) {
            formErrors["archive-entry-path"] = formErrors[
                "custom-start-command"
            ] =
                "Archive entry path or start command is required when extracting archive";
            isValid = false;
        }

        setValid(isValid);
        setFormErrors(formErrors);
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
                    file_path: form.get("file_path"),
                    start_command: form.get("start_command"),
                    no_internet: form.get("no_internet"),
                    no_screenshots: form.get("no_screenshots"),
                    extract_archive: form.get("extract_archive"),
                    archive_password: form.get("archive_password"),
                    archive_entry_path: form.get("archive_entry_path"),
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
            <form onSubmit={submitForm} ref={formRef}>
                <div className="mb-3">
                    <label htmlFor="form-file" className="form-label">
                        Sample file
                    </label>
                    <input
                        className="form-control"
                        type="file"
                        id="form-file"
                        name="file"
                        onChange={validateForm}
                        required
                    />
                    <FormError errors={formErrors} field="form-file" />
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
                    <PluginPicker name="plugins" onChange={validateForm} />
                    <FormError errors={formErrors} field="plugins" />
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
                        onChange={validateForm}
                        placeholder="(pick automatically)"
                    />
                    <FormError errors={formErrors} field="target-file-name" />
                </div>
                <div className="mb-3">
                    <label htmlFor="target-file-path" className="form-label">
                        Target file path
                    </label>
                    <input
                        type="text"
                        className="form-control"
                        id="target-file-path"
                        name="file_path"
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
                        onChange={validateForm}
                        placeholder="(pick automatically)"
                    />
                    <FormError
                        errors={formErrors}
                        field="custom-start-command"
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
                <div className="mb-3 form-check">
                    <input
                        className="form-check-input"
                        id="extract-archive"
                        type="checkbox"
                        name="extract_archive"
                        onChange={(ev) => {
                            setExtractArchive(ev.target.checked);
                            validateForm();
                        }}
                    />
                    <label
                        className="form-check-label"
                        htmlFor="extract-archive"
                    >
                        Extract archive
                    </label>
                </div>
                {extractArchive ? (
                    <>
                        <div className="mb-3">
                            <label
                                htmlFor="archive-password"
                                className="form-label"
                            >
                                Archive password (optional)
                            </label>
                            <input
                                type="text"
                                className="form-control"
                                id="archive-password"
                                name="archive_password"
                            />
                        </div>
                        <div className="mb-3">
                            <label
                                htmlFor="archive-entry-path"
                                className="form-label"
                            >
                                Path inside archive to execute
                            </label>
                            <input
                                type="text"
                                className="form-control"
                                id="archive-entry-path"
                                name="archive_entry_path"
                            />
                        </div>
                    </>
                ) : (
                    []
                )}
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
