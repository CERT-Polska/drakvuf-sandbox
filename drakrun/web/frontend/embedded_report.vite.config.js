import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { viteSingleFile } from "vite-plugin-singlefile";
import cssInjectedByJsPlugin from "vite-plugin-css-injected-by-js";
import { gzipSync } from "node:zlib";

function viteGzipBundle() {
    return {
        name: "vite:gzip-bundle-plugin",
        apply: "build",
        enforce: "post",
        generateBundle(_, bundle) {
            for (const [fileName, chunk] of Object.entries(bundle)) {
                if (chunk.type === "chunk" && fileName.endsWith(".js")) {
                    console.log("[gzip] ", fileName);
                    const originalCode = chunk.code;
                    const gzipped = gzipSync(
                        Buffer.from(originalCode, "utf-8"),
                    );
                    const base64 = gzipped.toString("base64");
                    const loader = `await import(URL.createObjectURL(new Blob([await new Response((await fetch('data:;base64,'+${base64})).body.pipeThrough(new DecompressionStream('gzip'))).text()],{type:'module'})))`;
                    chunk.code = loader;
                }
            }
        },
    };
}

// https://vite.dev/config/
export default defineConfig({
    root: "./embedded",
    plugins: [
        react(),
        cssInjectedByJsPlugin(),
        viteGzipBundle(),
        viteSingleFile(),
    ],
    define: {
        __APP_VERSION__: JSON.stringify(process.env.npm_package_version),
    },
    build: {
        outDir: "../dist/embedded",
        emptyOutDir: true,
    },
});
