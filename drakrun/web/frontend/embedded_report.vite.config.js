import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { viteSingleFile } from "vite-plugin-singlefile"
import fs from 'fs/promises';

// https://vite.dev/config/
export default defineConfig({
    root: "./embedded",
    plugins: [
        react(), viteSingleFile(),
    ],
    define: {
        '__APP_VERSION__': JSON.stringify(process.env.npm_package_version),
    },
    build: {
        outDir: '../dist/embedded',
        emptyOutDir: true,
    },
})
