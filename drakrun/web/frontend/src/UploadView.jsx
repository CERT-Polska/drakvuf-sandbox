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

function Collapse({ header, children, collapsed, onToggle }) {
    return (
        <div className="mb-3">
            <div className="d-flex align-items-center mb-2">
                <hr className="flex-grow-1" />

                <button
                    type="button"
                    className="btn btn-sm btn-link text-decoration-none px-2 d-flex align-items-center"
                    onClick={onToggle}
                >
                    <span className="me-1">{header}</span>
                    <span className="chevron">{collapsed ? "▼" : "▲"}</span>
                </button>
                <hr className="flex-grow-1" />
            </div>
            <div
                className={
                    "card card-body border-0 bg-light" +
                    (collapsed ? " d-none" : "")
                }
            >
                {children}
            </div>
        </div>
    );
}

function InfoPopover({ children }) {
    const [show, setShow] = useState(false);
    return (
        <span className="position-relative">
            <span
                className="ms-2 text-muted"
                style={{ cursor: "pointer" }}
                onMouseEnter={() => setShow(true)}
                onMouseLeave={() => setShow(false)}
                // Support non-mouse devices (e.g. mobile)
                onClick={() => setShow((state) => !state)}
            >
                ⓘ
            </span>
            {show && (
                <div
                    className="position-absolute bg-white border rounded p-2 shadow"
                    style={{ top: "100%", left: 0, zIndex: 10, width: "400px" }}
                >
                    {children}
                </div>
            )}
        </span>
    );
}

function UploadForm() {
    const [valid, setValid] = useState(true);
    const [submitted, setSubmitted] = useState(false);
    const formRef = useRef(undefined);
    const [formErrors, setFormErrors] = useState({});
    const [error, setError] = useState();
    const [analysisTime, setAnalysisTime] = useState(10);
    const [extractArchive, setExtractArchive] = useState(false);
    const [extraOptionsCollapsed, setExtraOptionsCollapsed] = useState(true);
    const navigate = useNavigate();

    const validateForm = useCallback(() => {
        const form = new FormData(formRef.current);
        const filename = form.get("file").name;
        const archiveEntryPath = form.get("archive_entry_path");
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
                "Path to execute in archive or start command is required when extracting archive";
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
                    start_method: form.get("start_method"),
                    start_working_dir: form.get("start_working_dir"),
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
        <form onSubmit={submitForm} ref={formRef}>
            <div className="mb-3">
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
                <label className="form-check-label" htmlFor="extract-archive">
                    Extract archive on the VM
                </label>
            </div>
            {extractArchive ? (
                <div className="mb-3">
                    <label htmlFor="archive-entry-path" className="form-label">
                        Path inside archive to execute
                        <InfoPopover>
                            Relative path of the file to execute after
                            extracting the archive
                        </InfoPopover>
                    </label>
                    <input
                        type="text"
                        className="form-control"
                        id="archive-entry-path"
                        name="archive_entry_path"
                        onChange={validateForm}
                    />
                    <FormError errors={formErrors} field="archive-entry-path" />
                </div>
            ) : (
                []
            )}
            {extractArchive ? (
                <div className="mb-3">
                    <label htmlFor="archive-password" className="form-label">
                        Archive password (optional)
                    </label>
                    <input
                        type="text"
                        className="form-control"
                        id="archive-password"
                        name="archive_password"
                    />
                </div>
            ) : (
                []
            )}
            <Collapse
                header="Extra options"
                collapsed={extraOptionsCollapsed}
                onToggle={() => setExtraOptionsCollapsed((state) => !state)}
            >
                <div className="mb-3">
                    <label className="form-label">Plugins:</label>
                    <PluginPicker name="plugins" onChange={validateForm} />
                    <FormError errors={formErrors} field="plugins" />
                </div>
                <div className="mb-3">
                    <label htmlFor="target-file-name" className="form-label">
                        Target file name
                        <InfoPopover>
                            Specify the name to assign to the file when it is
                            uploaded to the VM. By default, the file keeps the
                            same name as the one you uploaded. Use this if the
                            malware requires a specific name or if the uploaded
                            file doesn’t have the correct extension.
                        </InfoPopover>
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
                        <InfoPopover>
                            Choose the location on the VM where the file will be
                            uploaded. By default, files go to the Desktop. You
                            can use environment variables here (e.g.,
                            %USERPROFILE%).
                        </InfoPopover>
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
                        <InfoPopover>
                            Enter a custom command line to execute the sample on
                            the VM. This is passed directly to
                            CreateProcess/ShellExecute, so include the correct
                            file name. Note that environment variables are not
                            expanded in this field.
                        </InfoPopover>
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
                <div className="mb-3">
                    <label htmlFor="start-method" className="form-label">
                        Start method
                        <InfoPopover>
                            Select the method used to launch the sample on the
                            VM. CreateProcess requires a Windows executable (not
                            a script). "ShellExecute with runas verb" can be
                            used to force elevation if the sample needs higher
                            privileges and does not self-elevate.
                        </InfoPopover>
                    </label>
                    <select
                        className="form-select"
                        id="start-method"
                        name="start_method"
                    >
                        <option value="" selected>
                            default
                        </option>
                        <option value="createproc">CreateProcess</option>
                        <option value="shellexec">ShellExecute</option>
                        <option value="runas">
                            ShellExecute with runas verb (force elevate)
                        </option>
                    </select>
                </div>
                <div className="mb-3">
                    <label htmlFor="start-method" className="form-label">
                        Start working directory
                        <InfoPopover>
                            Define the working directory for the sample during
                            execution. By default, it is set to the "Target file
                            path". Environment variables are not expanded here.
                        </InfoPopover>
                    </label>
                    <input
                        type="text"
                        className="form-control"
                        id="custom-start-working-dir"
                        name="start_working_dir"
                        onChange={validateForm}
                        placeholder="(pick automatically)"
                    />
                    <FormError
                        errors={formErrors}
                        field="custom-start-working-dir"
                    />
                </div>
                <div className="row mb-3">
                    <div className="col-md-6">
                        <div className="form-check">
                            <input
                                className="form-check-input"
                                id="no-internet"
                                type="checkbox"
                                name="no_internet"
                            />
                            <label
                                className="form-check-label"
                                htmlFor="no-internet"
                            >
                                Disable Internet access
                            </label>
                        </div>
                    </div>
                    <div className="col-md-6">
                        <div className="form-check">
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
                    </div>
                </div>
            </Collapse>

            <div className="d-flex align-items-center">
                <button
                    className="btn btn-primary"
                    disabled={submitted || !valid}
                    type="submit"
                >
                    Analyze
                </button>
                {error ? (
                    <div className="text-danger ms-3">Error: {error}</div>
                ) : (
                    []
                )}
            </div>
        </form>
    );
}

export default function UploadView() {
    return (
        <div className="container py-5" style={{ maxWidth: "800px" }}>
            <div className="card">
                <div className="card-body">
                    <div className="d-flex align-items-center mb-3">
                        <div>
                            <h4 className="mb-0">Submit file for analysis</h4>
                            <small className="text-muted">
                                Detonate file inside malware sandbox
                            </small>
                        </div>
                    </div>
                    <UploadForm />
                </div>
            </div>
        </div>
    );
}
