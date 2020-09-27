import React from "react";

// TODO change this into a button, requires a little bit of styling
function TabItem({ active, value, onClick }) {
  return (
    <li className="nav-item">
      <a
        href="#/"
        className={"nav-link " + (active ? "active" : "")}
        onClick={onClick}
      >
        {value}
      </a>
    </li>
  );
}

function Tabs({ children, onChange, selected }) {
  if (children === undefined) {
    throw new Error("No tabs to render");
  }

  const betterChildren = React.Children.map(children, (child, i) => {
    return React.cloneElement(child, {
      active: selected === child.props.label,
      onClick: () => onChange(child.props.label),
    });
  });

  return <ul className="nav nav-tabs nav-bordered mb-3">{betterChildren}</ul>;
}

export { Tabs, TabItem };
