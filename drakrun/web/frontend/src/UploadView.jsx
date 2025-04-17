import CreatableSelect from "react-select/creatable";
import { useCallback, useState } from "react";

const createOption = (option) => ({ label: option, value: option });

const plugins = [
    createOption("apimon"),
    createOption("bsodmon"),
    createOption("clipboardmon"),
    createOption("codemon"),
    createOption("delaymon"),
    createOption("exmon"),
    createOption("fileextractor"),
    createOption("filetracer"),
    createOption("hidevm"),
    createOption("hidsim"),
    createOption("ipt"),
    createOption("memdump"),
    createOption("objmon"),
    createOption("procmon"),
    createOption("regmon"),
    createOption("socketmon"),
    createOption("syscalls"),
    createOption("tlsmon"),
    createOption("windowmon"),
];

const defaultPlugins = [
    createOption("apimon"),
    createOption("filetracer"),
    createOption("memdump"),
    createOption("procmon"),
    createOption("socketmon"),
    createOption("tlsmon"),
];

const pluginPickerStyles = {
    multiValue: (styles, { data }) => {
        if (!data.__isNew__)
            return { ...styles, backgroundColor: "rgba(0, 82, 204, 0.1)" };
        else return { ...styles, backgroundColor: "rgba(255, 86, 48, 0.1)" };
    },
    multiValueLabel: (styles, { data }) => {
        if (!data.__isNew__) return { ...styles, color: "rgb(0, 82, 204)" };
        else return { ...styles, color: "rgb(255, 86, 48)" };
    },
};

function PluginPicker({ onChange }) {
    const [chosenCustomPlugin, setChosenCustomPlugin] = useState(false);
    const onSelectChange = useCallback(
        (currentValue) => {
            setChosenCustomPlugin(currentValue.some((data) => data.__isNew__));
            if (onChange) onChange(currentValue);
        },
        [onChange],
    );
    return (
        <div>
            <CreatableSelect
                isMulti
                options={plugins}
                styles={pluginPickerStyles}
                onChange={onSelectChange}
                defaultValue={defaultPlugins}
            />
            {chosenCustomPlugin ? (
                <div className="text-danger small">
                    Picked custom plugin which may be not supported by Drakvuf
                    Sandbox
                </div>
            ) : (
                []
            )}
        </div>
    );
}

export default function UploadView(props) {
    return (
        <div className="container-fluid px-4">
            <h1 className="m-4 h4">Upload sample</h1>
            <div className="mb-3">
                <label htmlFor="formFile" className="form-label">
                    Sample file
                </label>
                <input className="form-control" type="file" id="formFile" />
            </div>
            <div className="mb-3">
                <label htmlFor="customRange2" className="form-label">
                    Analysis time
                </label>
                <input
                    type="range"
                    className="form-range"
                    min="0"
                    max="15"
                    id="customRange2"
                />
            </div>
            <div className="mb-3">
                <label htmlFor="customRange2" className="form-label">
                    Plugins
                </label>
                <PluginPicker />
            </div>
            <div className="mb-3">
                <label
                    htmlFor="exampleFormControlInput1"
                    className="form-label"
                >
                    Custom file name
                </label>
                <input
                    type="text"
                    className="form-control"
                    id="exampleFormControlInput1"
                />
            </div>
            <div className="mb-3">
                <label
                    htmlFor="exampleFormControlInput1"
                    className="form-label"
                >
                    Start command
                </label>
                <input
                    type="text"
                    className="form-control"
                    id="exampleFormControlInput1"
                />
            </div>
        </div>
    );
}
