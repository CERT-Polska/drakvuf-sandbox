import { useCallback, useMemo } from "react";
import CreatableSelect from "react-select/creatable";

const methodPickerStyles = {
    multiValue: (styles, { data }) => {
        return { ...styles, backgroundColor: "rgba(255, 86, 48, 0.1)" };
    },
    multiValueLabel: (styles, { data }) => {
        return { ...styles, color: "rgb(255, 86, 48)" };
    },
};

export function MethodFilterPicker({ onFilterChange, methods, currentFilter }) {
    const onSelectChange = useCallback(
        (value) => {
            return onFilterChange(value.map((v) => v.value));
        },
        [onFilterChange],
    );
    const methodOptions = useMemo(
        () => methods.map((option) => ({ label: option, value: option })),
        [methods],
    );
    const currentFilterOptions = useMemo(
        () => currentFilter.map((option) => ({ label: option, value: option })),
        [currentFilter],
    );
    return (
        <div>
            <CreatableSelect
                isMulti
                options={methodOptions}
                value={currentFilterOptions}
                styles={methodPickerStyles}
                onChange={onSelectChange}
            />
        </div>
    );
}
