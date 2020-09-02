import React, { useState, useEffect, useRef } from "react";
import OptionPicker from "./OptionPicker";
import InfiniteLoader from "react-window-infinite-loader";
import AutoSizer from "react-virtualized-auto-sizer";
import { FixedSizeList as List } from "react-window";
import { Tabs, TabItem } from "./Tabs.js";
import api from "./api";

function LogBrowser({
  // Log entry component
  children,
  // Index of log file we want to browse
  index,
  // Function (from, to) => Promise<bytes>
  queryData,
}) {
  // chunks object layout:
  // {
  //   0: [chunk 0 entries - objects],
  //   1: [chunk 1 entries - objects],
  //   ...
  // }
  const [chunks, setChunks] = useState(null);
  const [lines, setLines] = useState(index.num_lines);
  const pending = useRef(null);

  // No index or only single marker => load only single chunk
  const singleChunk = index === null || index.markers.length === 1;

  // Load first chunk
  useEffect(() => {
    if (index !== null) {
      setLines(index.num_lines);
    }
    queryData(0, singleChunk ? null : index.markers[1].offset - 1).then(
      (entries) => {
        if (singleChunk) {
          setLines(entries.length);
        }
        setChunks({ 0: entries });
      }
    );
  }, [singleChunk, index, queryData]);

  useEffect(() => {
    if (pending.current !== null) {
      pending.current();
      pending.current = null;
    }
  }, [chunks]);

  if (chunks === null) {
    return "Loading...";
  }

  const findChunkIndex = (lineIndex) => {
    if (singleChunk) {
      return 0;
    }

    const markers = index.markers;
    for (let i = 0; i < markers.length; i++) {
      const chunk = markers[i];
      if (chunk.line > lineIndex) {
        return i - 1;
      }
    }
    return markers.length - 1;
  };

  const isItemLoaded = (entry) => {
    const chunkIdx = findChunkIndex(entry);
    // Data is loaded in chunks, so if chunk is missing, so is the item
    return chunks[chunkIdx] !== undefined;
  };

  const loadMoreItems = (startIndex, stopIndex) => {
    // console.log(`Requesting from `, startIndex, " to ", stopIndex);
    const startChunkIndex = findChunkIndex(startIndex);
    const endChunkIndex = findChunkIndex(stopIndex);

    let promises = [];
    // console.log(`Downloading from `, startChunkIndex, " to ", endChunkIndex);
    for (let idx = startChunkIndex; idx <= endChunkIndex; idx++) {
      const chunk = index.markers[idx];
      const isLastChunk = idx === index.markers.length - 1;
      const nextChunk = index.markers[idx + 1];
      const endOffset = isLastChunk ? null : nextChunk.offset;

      const promise = queryData(chunk.offset, endOffset).then((chunk) => {
        return [idx, chunk];
      });

      promises.push(promise);
    }

    let updatedPromise = new Promise((resolve, _) => {
      // Register resolver
      pending.current = resolve;
    });

    // When all chunks are loaded, update state
    Promise.all(promises).then((results) => {
      const newChunks = {};
      for (const [idx, chunk] of results) {
        newChunks[idx] = chunk;
      }
      setChunks({ ...chunks, ...newChunks });
    });

    return updatedPromise;
  };

  const loader = function ({ width, height }) {
    return (
      <InfiniteLoader
        isItemLoaded={isItemLoaded}
        loadMoreItems={loadMoreItems}
        itemCount={lines}
        minimumBatchSize={2000}
      >
        {({ onItemsRendered, ref }) => (
          <List
            height={height}
            width={width}
            itemCount={lines}
            itemSize={30}
            onItemsRendered={onItemsRendered}
            ref={ref}
          >
            {(props) => {
              const lineIndex = props.index;

              const chunkIndex = findChunkIndex(lineIndex);
              const chunk = chunks[chunkIndex];
              if (chunk === undefined) {
                return children({
                  entry: undefined,
                  index: lineIndex,
                  style: props.style,
                });
              }
              const lineOffset = index ? index.markers[chunkIndex].line : 0;
              const entry = chunk[lineIndex - lineOffset];
              return children({
                entry,
                index: lineIndex,
                style: props.style,
              });
            }}
          </List>
        )}
      </InfiniteLoader>
    );
  };
  return <AutoSizer>{loader}</AutoSizer>;
}

const SERVICE_LOGS = ["drakrun.log", "drak-postprocess.log"];

const DrakvufRow = ({ entry, style }) => {
  let content;
  let displayed = { ...entry };
  if (entry === undefined) {
    content = "Loading...";
  } else {
    content = (
      <code style={{ whiteSpace: "nowrap" }}>{JSON.stringify(displayed)}</code>
    );
  }

  return (
    <div style={style} className="d-flex flex-row align-content-stretch">
      <div className="p-1">{content}</div>
    </div>
  );
};

function formatTimestamp(timestamp) {
  const newDate = new Date();
  newDate.setTime(timestamp * 1000);
  const dateString = newDate.toUTCString();
  return dateString;
}

const ServiceRow = ({ entry, index, style }) => {
  if (entry === undefined) {
    return "Loading...";
  }
  return (
    <div style={style} className="d-flex flex-row align-content-stretch">
      <div className="p-1">
        <div>
          <code style={{ whiteSpace: "nowrap" }}>{entry.message}</code>
        </div>
      </div>
    </div>
  );
};

class AnalysisLogs extends React.Component {
  constructor(props) {
    super(props);
    this.analysisID = this.props.match.params.analysis;

    this.state = {
      currentLog: null,
      currentTab: "drakvuf",
      logList: [],
      index: null,
    };

    this.selectionChanged = this.selectionChanged.bind(this);
    this.getLogChunk = this.getLogChunk.bind(this);
    this.setTab = this.setTab.bind(this);
  }

  setTab(tab) {
    this.setState({ currentTab: tab });
  }

  async getLogChunk(from, to) {
    const chunks = await api.getLogRange(
      this.analysisID,
      this.state.currentLog.split(".")[0],
      from,
      to
    );
    if (chunks) {
      return chunks.request.response.split("\n").map((line) => {
        try {
          return JSON.parse(line);
        } catch (e) {
          console.log(e);
        }
        return undefined;
      });
    }
    return null;
  }

  async componentDidMount() {
    const logs = await api.listLogs(this.analysisID);
    if (logs) {
      this.setState({
        logList: logs.data,
      });
    }
    const defaltSelection = logs.data[0].split("/")[1];
    await this.selectionChanged(defaltSelection);
  }

  async selectionChanged(newSelection) {
    try {
      const index = await api.logIndex(
        this.analysisID,
        newSelection.split(".")[0]
      );
      this.setState({ index: index.data, currentLog: newSelection });
    } catch {
      this.setState({ index: null, currentLog: newSelection });
    }
  }

  render() {
    const handleMissingIndex = (index) => {
      if (index !== null) {
        return index;
      }
      return {
        num_lines: 0,
        markers: [{ line: 0, offset: 0 }],
      };
    };

    const isServiceLog = (name) =>
      SERVICE_LOGS.some((s) => {
        return name.includes(s);
      });

    const intoOption = (obj) => {
      const log_name = obj.split("/")[1];
      return { key: log_name, value: log_name };
    };

    const logClassPredicate = {
      services: isServiceLog,
      drakvuf: (log_name) => !isServiceLog(log_name),
    };

    const logClass = logClassPredicate[this.state.currentTab] || ((s) => true);

    const entryComponent = {
      services: ServiceRow,
      drakvuf: DrakvufRow,
    };

    if (this.state.currentLog === null || this.state.currentTab === null)
      return "Loading..";

    const content = (
      <>
        <Tabs onChange={this.setTab}>
          <TabItem label={"drakvuf"} value={"DRAKVUF"} />
          <TabItem label={"services"} value={"Services"} />
        </Tabs>
        <div className="row mb-2">
          <div className="col">
            <OptionPicker
              data={this.state.logList.filter(logClass).map(intoOption)}
              onChange={this.selectionChanged}
            />
          </div>
          <a
            download={this.state.currentLog}
            href={"/log/" + this.analysisID + "/" + this.state.currentLog}
            className="btn btn-primary"
          >
            Download log
          </a>
        </div>

        <div style={{ flex: 1 }}>
          <LogBrowser
            index={handleMissingIndex(this.state.index)}
            queryData={this.getLogChunk}
          >
            {entryComponent[this.state.currentTab]}
          </LogBrowser>
        </div>
      </>
    );

    return (
      <div
        className="App container-fluid d-flex"
        style={{ flex: 1, flexFlow: "column" }}
      >
        <div className="page-title-box">
          <h4 className="page-title">Analysis logs</h4>
        </div>

        <div className="card tilebox-one" style={{ flex: 1 }}>
          <div className="card-body d-flex" style={{ flexFlow: "column" }}>
            {this.state.currentLog !== null ? content : ""}
          </div>
        </div>
      </div>
    );
  }
}

export default AnalysisLogs;
