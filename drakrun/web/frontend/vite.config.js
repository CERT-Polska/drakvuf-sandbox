import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
    plugins: [react()],
    define: {
        '__APP_VERSION__': JSON.stringify(process.env.npm_package_version),
    },
    // dev-server
    server: {
        host: "0.0.0.0",
        port: 3000,
        strictPort: true,
        proxy: (
            process.env.PROXY_BACKEND_URL ? {
                "/api": {
                    target: process.env.PROXY_BACKEND_URL,
                    changeOrigin: true,
                },
            } : {}
        ),
    }
})
