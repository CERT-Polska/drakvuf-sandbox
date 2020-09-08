import React, { useState, useEffect, useRef } from "react";
import PropTypes from "prop-types";
import InfiniteLoader from "react-window-infinite-loader";
import AutoSizer from "react-virtualized-auto-sizer";
import { FixedSizeList as List } from "react-window";

// Empirically chosen average number of items in 1MiB chunk
// where size of each entry == size of syscalls log / number of lines
const BATCH_SIZE = 2000;

/**
 * @typedef Marker
 * @prop {number} line Index of first line this chunk contains
 * @prop {number} offset Offset in bytes from start of the file
 */

/**
 * @typedef FileIndex
 * @prop {Marker[]} markers Array of markers defining file chunks
 * @prop {number} num_lines Number of lines in file
 * @prop {number} chunk_size Size of chunk in bytes
 */

/**
 * @param {FileIndex} index FileIndex to use for search
 * @param {number} lineIndex Line of interest
 * @return {number} Index of chunk containing lineIndex line
 */
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

  /**
   * Check if given item is loaded within the context
   * of index - prop and chunks - state
   * @param {number} entry Index of entry
   * @return {boolean} Is item loaded
   */
  const isItemLoaded = (entry) => {
    const chunkIdx = findChunkIndex(index, entry);
    // Data is loaded in chunks, so if chunk is missing, so is the item
    return chunks[chunkIdx] !== undefined;
  };

  /**
   * Load more items from backend to display in browser
   * @param {number} startIndex First index to load
   * @param {number} stopIndex Last index to load (inclusive)
   * @return {any} Promise that resolves when all items in this range are loaded
   */
  const loadMoreItems = (startIndex, stopIndex) => {
    const startChunkIndex = findChunkIndex(index, startIndex);
    const endChunkIndex = findChunkIndex(index, stopIndex);

    let promises = [];
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

LogBrowser.propTypes = {
  children: PropTypes.elementType.isRequired,
  index: PropTypes.object.isRequired,
  queryData: PropTypes.func,
};

export default LogBrowser;
