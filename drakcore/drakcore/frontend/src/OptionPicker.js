import React from "react";

function OptionPicker({ className, data, onChange, selected }) {
  const renderOption = (item, index) => (
    <option key={index} value={item.key}>
      {item.value}
    </option>
  );

  return (
    <select
      value={selected || ""}
      className={`form-control ${className || ""}`}
      onChange={(event) => onChange(event.target.value)}
    >
      {data.map(renderOption)}
    </select>
  );
}

export default OptionPicker;
