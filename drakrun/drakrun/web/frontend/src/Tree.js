import React, { useState } from "react";
import Graph from "react-graph-vis";

const options = {
    nodes: {
      shape: 'box',
      borderWidthSelected: 2,
      color: '#1976d2',
      widthConstraint: {
        maximum: 300,
      }
    },
    layout:{
      improvedLayout: true,
      hierarchical: {
        levelSeparation: 900,
        nodeSpacing: 80,
        treeSpacing: 50,
        sortMethod: "hubsize",
        direction: 'LR',
        },
      },
    interaction: { hover: true },
    physics: {
      enabled: false
      },
    edges: {
      color: "white",
      smooth: {
        type: "cubicBezier",
        forceDirection: "horizontal",
        roundness: 0.6,
      },
    }
  };

function generateNodes(report, TTP, file, registry) {
    let selected_pids = Object.keys(report["processes"])
    let nodes = [];

    if(TTP) {
        selected_pids = selected_pids.filter((pid) => report["processes"][pid]["ttps"].reduce((acc, ttp) => (acc.add(...ttp["att&ck"])), new Set()).has(TTP))
    }
    if(file) {
        selected_pids = selected_pids.filter((pid) => report["processess"][pid]["files"].includes(file));
    }
    if(registry){
        selected_pids = selected_pids.filter((pid) => report["processes"][pid]["registry"].includes(registry));
    }

    for (let pid of Object.keys(report["processes"])){
        if(selected_pids.includes(pid) && (TTP || file || registry)) {
            // mark nodes that have the ttp/file/regkey at hand with a different color
            nodes.push({id: pid, label: report["processes"][pid]["procname"], color: 'red'});
        } else{
            // default blueish color
            nodes.push({id: pid, label: report["processes"][pid]["procname"]});
        }
    }
    return nodes;
};

export default function ProcessTree({report, TTP, file, registry, onSelectProcess}) {
    const nodes = 0;
    const state = {
        counter: 5,
        graph: {
            nodes:
                generateNodes(report, TTP, file, registry),
            edges:
                Object.keys(report["processes"]).map((parent) => report["processes"][parent]["children"].map((child) => ({from: parent, to: child}))).flat()
            
        },
        events: {
            selectNode: ({ nodes}) => {
                onSelectProcess(...nodes);
            },
            deselectNode: ({}) => {
                onSelectProcess(false);
            },
        }
        };
    const { graph, events } = state;
    return (
    <Graph graph={graph} options={options} events={events} style={{ height: "100vh" }} getNetwork={network => {setTimeout(()=>{
    network.setOptions({
        layout:{
            hierarchical: false
            },
        });}, 1000)}} />
    )
    }