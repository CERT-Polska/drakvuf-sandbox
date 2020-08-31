import React, { useState, useEffect } from "react";

function TabItem({ active, value, onClick }) {
  return (
    <li className="nav-item">
      <a
        href="#"
        className={"nav-link " + (active ? "active" : "")}
        onClick={onClick}
      >
        {value}
      </a>
    </li>
  );
}

function Tabs({ defaultTab, children, onChange }) {
  const [active, setActive] = useState(defaultTab || children[0].props.label);

  useEffect(() => {
    onChange(active);
  }, [onChange, active]);

  const betterChildren = React.Children.map(children, (child, i) => {
    return React.cloneElement(child, {
      active: active === child.props.label,
      onClick: () => setActive(child.props.label),
    });
  });

  return <ul className="nav nav-tabs nav-bordered mb-3">{betterChildren}</ul>;
}

export { Tabs, TabItem };
