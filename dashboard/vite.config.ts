// Vite config for the Tauri shell.
//
// The fixed port + strictPort matter: Tauri's dev URL points at this
// exact host:port (see src-tauri/tauri.conf.json#build.devUrl), so we
// must refuse to fall back to a different port silently.

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? { protocol: "ws", host, port: 1421 }
      : undefined,
    watch: {
      // Avoid recompiling on Rust changes — the Tauri side handles that itself.
      ignored: ["**/src-tauri/**"],
    },
  },
});
