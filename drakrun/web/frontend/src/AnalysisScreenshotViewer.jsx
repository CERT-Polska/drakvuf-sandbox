import Zoom from "react-medium-image-zoom";
import "react-medium-image-zoom/dist/styles.css";
import { useAnalysisReport } from "./AnalysisReportContext.jsx";

export function AnalysisScreenshotViewer({ analysis }) {
    const { getScreenshotURL } = useAnalysisReport();
    return (
        <div className="container-fluid">
            <div className="row">
                {Array.from(Array(analysis.screenshots).keys()).map(
                    (_, idx) => (
                        <div className="col-lg-2" key={`screenshot-${idx + 1}`}>
                            <Zoom>
                                <img
                                    alt={`screenshot-${idx + 1}`}
                                    src={getScreenshotURL(analysis.id, idx + 1)}
                                    className="img-thumbnail"
                                    style={{ cursor: "pointer" }}
                                />
                            </Zoom>
                        </div>
                    ),
                )}
            </div>
        </div>
    );
}
