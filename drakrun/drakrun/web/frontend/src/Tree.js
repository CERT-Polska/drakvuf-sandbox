import React from "react";
import Graph from "react-graph-vis";

const options = {
  nodes: {
    shape: "box",
    borderWidthSelected: 2,
    color: "#1976d2",
    widthConstraint: {
      maximum: 300,
    },
  },
  layout: {
    improvedLayout: true,
    hierarchical: {
      levelSeparation: 900,
      nodeSpacing: 80,
      treeSpacing: 50,
      sortMethod: "hubsize",
      direction: "LR",
    },
  },
  interaction: { hover: true },
  physics: {
    enabled: false,
  },
  edges: {
    color: "white",
    smooth: {
      type: "cubicBezier",
      forceDirection: "horizontal",
      roundness: 0.6,
    },
  },
};

function generateNodes(report, TTP, file, registry) {
  let selected_pids = Object.keys(report["processes"]);
  let nodes = [];

  if (TTP) {
    selected_pids = selected_pids.filter((pid) => {
      let ttps_set = new Set();
      report["processes"][pid]["ttps"].forEach((ttp) => {
        ttp["att&ck"].forEach((attck_name) => {
          ttps_set.add(attck_name);
        });
      });
      return ttps_set.has(TTP);
    });
  }
  if (file) {
    selected_pids = selected_pids.filter((pid) =>
      report["processes"][pid]["files"].includes(file)
    );
  }
  if (registry) {
    selected_pids = selected_pids.filter((pid) =>
      report["processes"][pid]["registry_keys"].includes(registry)
    );
  }

  for (let pid of Object.keys(report["processes"])) {
    if (selected_pids.includes(pid) && (TTP || file || registry)) {
      // mark nodes that have the ttp/file/regkey at hand with a different color
      nodes.push({
        id: pid,
        label: report["processes"][pid]["procname"],
        color: "#2ae300",
      });
    } else {
      // default blueish color
      nodes.push({
        id: pid,
        label: report["processes"][pid]["procname"],
        color: "#1976d2",
      });
    }
  }
  return nodes;
}

export default function ProcessTree({
  report,
  selectedTTP,
  selectedFile,
  selectedRegistry,
  onSelectProcess,
}) {
  const nodes = generateNodes(
    report,
    selectedTTP,
    selectedFile,
    selectedRegistry
  );

  const state = {
    counter: 5,
    graph: {
      nodes: nodes,
      edges: Object.keys(report["processes"])
        .map((parent) =>
          report["processes"][parent]["children"].map((child) => ({
            from: parent,
            to: child,
          }))
        )
        .flat(),
    },
    events: {
      selectNode: ({ nodes }) => {
        onSelectProcess(...nodes);
      },
      deselectNode: () => {
        onSelectProcess(false);
      },
    },
  };
  const { graph, events } = state;
  return (
    <Graph
      graph={graph}
      options={options}
      events={events}
      style={{ height: "100vh" }}
      getNetwork={(network) => {
        setTimeout(() => {
          network.setOptions({
            layout: {
              hierarchical: false,
            },
          });
        }, 1000);
      }}
    />
  );
}