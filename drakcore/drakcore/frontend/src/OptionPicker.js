import React, { useEffect, useState } from "react";

function OptionPicker({ className, data, onChange }) {
  const [selected, setSelected] = useState(null);

  const renderOption = (item, index) => (
    <option key={index} value={item.key}>
      {item.value}
    </option>
  );

  // Update current selection on data change
  // If the state cannot be mapped, default to first entry
  useEffect(() => {
    if (!data.map((v) => v.key).includes(selected)) {
      setSelected(data[0].key);
    }
  }, [selected, data]);

  // Notify parent if selection occurred
  useEffect(() => {
    if (selected !== null) {
      onChange(selected);
    }
  }, [onChange, selected]);

  return (
    <select
      value={selected || ""}
      className={`form-control ${className || ""}`}
      onChange={(event) => setSelected(event.target.value)}
    >
      {data.map(renderOption)}
    </select>
  );
}

export default OptionPicker;
