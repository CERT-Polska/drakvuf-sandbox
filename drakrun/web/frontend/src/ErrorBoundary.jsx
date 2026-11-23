import { Component } from "react";
import { formatApiError } from "./errors.js";

/**
 * Catches exceptions thrown while rendering its children and shows an error
 * box instead of unmounting the whole app. It does not see errors from event
 * handlers or promises; report those with useNotifications().notifyError.
 *
 * Give it a `key` that changes on navigation to reset it on another page.
 */
export class ErrorBoundary extends Component {
    constructor(props) {
        super(props);
        this.state = { error: null };
        this.reset = this.reset.bind(this);
    }

    static getDerivedStateFromError(error) {
        return { error };
    }

    componentDidCatch(error, info) {
        console.error("Render error caught by ErrorBoundary", error, info);
    }

    reset() {
        this.setState({ error: null });
    }

    render() {
        if (this.state.error === null) {
            return this.props.children;
        }
        return (
            <div className="container-fluid px-4 py-4">
                <div className="alert alert-danger" role="alert">
                    <h5 className="alert-heading">
                        Something went wrong while displaying this page
                    </h5>
                    <p className="mb-2 font-monospace small">
                        {formatApiError(this.state.error)}
                    </p>
                    <p className="mb-3 small">
                        Details are in the browser console.
                    </p>
                    <button
                        type="button"
                        className="btn btn-outline-danger btn-sm"
                        onClick={this.reset}
                    >
                        Try again
                    </button>
                </div>
            </div>
        );
    }
}
