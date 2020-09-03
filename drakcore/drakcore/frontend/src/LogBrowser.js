import React, { useState, useEffect, useRef } from "react";
import InfiniteLoader from "react-window-infinite-loader";
import AutoSizer from "react-virtualized-auto-sizer";
import { FixedSizeList as List } from "react-window";

// Empirically chosen average number of items in 1MiB chunk
// where size of each entry == size of syscalls log / number of lines
const BATCH_SIZE = 2000;

function findChunkIndex(index, lineIndex) {
  const markers = index.markers;
  if (markers.length === 1) {
    return 0;
  }

  for (let i = 0; i < markers.length; i++) {
    const chunk = markers[i];
    if (chunk.line > lineIndex) {
      return i - 1;
    }
  }

  return markers.length - 1;
}

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
  const singleChunk = index.markers.length === 1;

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

  const isItemLoaded = (entry) => {
    const chunkIdx = findChunkIndex(index, entry);
    // Data is loaded in chunks, so if chunk is missing, so is the item
    return chunks[chunkIdx] !== undefined;
  };

  const loadMoreItems = (startIndex, stopIndex) => {
    // console.log(`Requesting from `, startIndex, " to ", stopIndex);
    const startChunkIndex = findChunkIndex(index, startIndex);
    const endChunkIndex = findChunkIndex(index, stopIndex);

    let promises = [];
    // console.log(`Downloading from `, startChunkIndex, " to ", endChunkIndex);
    for (let idx = startChunkIndex; idx <= endChunkIndex; idx++) {
      const chunk = index.markers[idx];
      const isLastChunk = idx === index.markers.length - 1;
      const nextChunk = index.markers[idx + 1];
      const endOffset = isLastChunk ? null : nextChunk.offset;

      const promise = queryData(chunk.offset, endOffset).then((chunk) => [
        idx,
        chunk,
      ]);

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

  const browserItem = (props) => {
    const lineIndex = props.index;

    const chunkIndex = findChunkIndex(index, lineIndex);
    const chunk = chunks[chunkIndex];

    let entry;
    if (chunk !== undefined) {
      const lineOffset = index ? index.markers[chunkIndex].line : 0;
      entry = chunk[lineIndex - lineOffset];
    }

    return children({
      entry,
      index: lineIndex,
      style: props.style,
    });
  };

  const loader = function ({ width, height }) {
    return (
      <InfiniteLoader
        isItemLoaded={isItemLoaded}
        loadMoreItems={loadMoreItems}
        itemCount={lines}
        minimumBatchSize={BATCH_SIZE}
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
            {browserItem}
          </List>
        )}
      </InfiniteLoader>
    );
  };
  return <AutoSizer>{loader}</AutoSizer>;
}

export default LogBrowser;
