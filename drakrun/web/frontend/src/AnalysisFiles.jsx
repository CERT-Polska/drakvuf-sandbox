import { use, useCallback, useEffect, useRef, useState } from "react";
import { getAnalysisFileList } from "./api.js";
import { CanceledError } from "axios";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faDownload, faFile } from "@fortawesome/free-solid-svg-icons";
import Modal from "react-modal";
import JSZip from "jszip";
import JSZipUtils from "jszip-utils";

let BASE_URL = "";
if (import.meta.env.VITE_API_SERVER) {
    BASE_URL = import.meta.env.VITE_API_SERVER;
} else {
    BASE_URL = "/api";
}

Modal.setAppElement("#root");

function urlToPromise(url) {
    return new Promise(function (resolve, reject) {
        JSZipUtils.getBinaryContent(url, function (err, data) {
            if (err) {
                reject(err);
            } else {
                resolve(data);
            }
        });
    });
}

function FileTree({ fileList, analysisId }) {
    return (
        <ul
            style={{ overflow: "auto", marginLeft: "8pt" }}
            className="list-unstyled"
        >
            {fileList.map((file, idx) => {
                return (
                    <li key={`f-${idx}`}>
                        <span className="text-nowrap font-monospace">
                            <FontAwesomeIcon
                                icon={faFile}
                                className="me-3 text-primary"
                            />
                            <a
                                href={`${BASE_URL}/files/${analysisId}/download?filename=${encodeURIComponent(file)}`}
                            >
                                {file}
                            </a>
                        </span>
                    </li>
                );
            })}
        </ul>
    );
}

export function AnalysisZipDownload({ files, analysisId }) {
    const [modalOpened, setModalOpened] = useState(false);
    const [modalMessage, setModalMessage] = useState("");
    const [downloadFinished, setDownloadFinished] = useState(false);
    const [blobURL, setBlobURL] = useState(null);
    const modalStyle = {
        content: {
            top: "50%",
            left: "50%",
            right: "auto",
            bottom: "auto",
            marginRight: "-50%",
            transform: "translate(-50%, -50%)",
            maxHeight: "100%",
        },
    };

    const makeZip = useCallback(() => {
        const zip = new JSZip();
        for (let file of files) {
            zip.file(
                file,
                urlToPromise(
                    `${BASE_URL}/files/${analysisId}/download?filename=${encodeURIComponent(file)}`,
                ),
                { binary: true },
            );
        }
        zip.generateAsync({ type: "blob" }, (metadata) => {
            let msg = "progression : " + metadata.percent.toFixed(2) + " %";
            if (metadata.currentFile) {
                msg += ", current file = " + metadata.currentFile;
            }
            setModalMessage(msg);
        }).then(
            (blob) => {
                setBlobURL(URL.createObjectURL(blob));
                setModalMessage("");
                setDownloadFinished(true);
            },
            (err) => {
                setModalMessage(err);
                setDownloadFinished(true);
            },
        );
    }, [files, analysisId]);

    const startDownload = useCallback(() => {
        setDownloadFinished(false);
        setModalOpened(true);
        makeZip();
    }, [makeZip]);

    const closeModal = useCallback(() => {
        if (blobURL) {
            URL.revokeObjectURL(blobURL);
            setBlobURL(null);
        }
        setModalOpened(false);
    }, [blobURL]);

    return (
        <>
            <Modal
                isOpen={modalOpened}
                onRequestClose={downloadFinished ? closeModal : undefined}
                contentLabel="Downloading analysis..."
                style={modalStyle}
            >
                <div className="text-center">
                    {downloadFinished ? (
                        blobURL ? (
                            <div>
                                <strong>
                                    Analysis downloaded successfully.
                                </strong>
                                <br />
                                Click on the link below to store it:
                            </div>
                        ) : (
                            <div>Download failed</div>
                        )
                    ) : (
                        <div>Downloading analysis files...</div>
                    )}

                    <span className="text-muted">{modalMessage}</span>
                    {downloadFinished ? (
                        <>
                            {blobURL ? (
                                <div>
                                    <a
                                        href={blobURL}
                                        download={`${analysisId}.zip`}
                                    >{`${analysisId}.zip`}</a>
                                </div>
                            ) : (
                                []
                            )}
                        </>
                    ) : (
                        []
                    )}
                </div>
            </Modal>
            <div>
                <button
                    className="btn btn-primary mb-2"
                    onClick={() => startDownload()}
                >
                    <FontAwesomeIcon icon={faDownload} className="me-2" />
                    Download all
                </button>
            </div>
        </>
    );
}

export function AnalysisFilesViewer({ analysisId }) {
    const [files, setFiles] = useState();
    const [error, setError] = useState();

    useEffect(() => {
        const abortController = new AbortController();
        setFiles(undefined);
        getAnalysisFileList({ analysisId, abortController })
            .then((response) => {
                setFiles(response.slice().sort());
            })
            .catch((error) => {
                if (!(error instanceof CanceledError)) {
                    setError(error);
                    console.error(error);
                }
            });
        return () => {
            abortController.abort();
        };
    }, [analysisId]);

    if (typeof error !== "undefined") {
        return <div className="text-danger">Error: {error.toString()}</div>;
    }

    if (typeof files === "undefined") {
        return <div>Loading analysis files list...</div>;
    }

    return (
        <div className="container-fluid">
            <div className="row">
                <AnalysisZipDownload files={files} analysisId={analysisId} />
                <FileTree fileList={files} analysisId={analysisId} />
            </div>
        </div>
    );
}
