import { useCallback, useState } from "react";
import CreatableSelect from "react-select/creatable";

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

export function PluginList({ plugins }) {
    return (
        <div className="d-flex flex-wrap flex-row">
            {plugins.map((plugin) => (
                <div
                    className="plugin-badge"
                    style={{
                        backgroundColor: "rgba(0, 82, 204, 0.1)",
                        color: "rgb(0, 82, 204)",
                    }}
                    key={plugin}
                >
                    {plugin}
                </div>
            ))}
        </div>
    );
}

export function PluginPicker({ onChange, name }) {
    const [warning, setWarning] = useState(undefined);
    const onSelectChange = useCallback(
        (currentValue) => {
            if (currentValue.some((data) => data.__isNew__)) {
                setWarning(
                    "Picked custom plugin which may be not supported by Drakvuf Sandbox",
                );
            } else if (
                currentValue.length > 0 &&
                !currentValue.some((data) => data.value === "procmon")
            ) {
                setWarning(
                    "It's recommended to include 'procmon' plugin for complete process information",
                );
            } else {
                setWarning(undefined);
            }
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
                name={name}
            />
            {warning ? <div className="text-danger small">{warning}</div> : []}
        </div>
    );
}
