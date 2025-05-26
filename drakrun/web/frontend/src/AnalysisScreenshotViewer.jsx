import Zoom from "react-medium-image-zoom";
import "react-medium-image-zoom/dist/styles.css";

let BASE_URL = "";
if (import.meta.env.VITE_API_SERVER) {
    BASE_URL = import.meta.env.VITE_API_SERVER;
} else {
    BASE_URL = "/api";
}

export function AnalysisScreenshotViewer({ analysis }) {
    return (
        <div className="container-fluid">
            <div className="row">
                {Array.from(Array(analysis.screenshots).keys()).map(
                    (_, idx) => (
                        <div className="col-lg-2" key={`screenshot-${idx + 1}`}>
                            <Zoom>
                                <img
                                    alt={`screenshot-${idx + 1}`}
                                    src={`${BASE_URL}/screenshot/${analysis.id}/${idx + 1}`}
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
