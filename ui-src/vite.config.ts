import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import { viteSingleFile } from 'vite-plugin-singlefile';
import { mockApi } from './mock/api.ts';

/**
 * One HTML file, and nothing else.
 *
 * The console is served by the proxy being debugged and has to load with the
 * network it is inspecting switched off, so every byte — CSS, JS, the editor —
 * is inlined into `dist/index.html`, which Rust then `include_str!`s. Anything
 * that would become a second request (a chunk, a font, a CDN script) is a bug.
 */
export default defineConfig({
  base: './',
  plugins: [vue(), mockApi(), viteSingleFile({ removeViteModuleLoader: true })],
  // Nothing here is written with the Options API, and none of it wants to be
  // inspectable by the Vue devtools from inside a proxy binary.
  define: {
    __VUE_OPTIONS_API__: 'false',
    __VUE_PROD_DEVTOOLS__: 'false',
    __VUE_PROD_HYDRATION_MISMATCH_DETAILS__: 'false',
  },
  build: {
    target: 'es2022',
    // A single file has nowhere to put a source map, and the inline kind would
    // triple the size of something that ships inside a binary.
    sourcemap: false,
    cssCodeSplit: false,
    assetsInlineLimit: 100_000_000,
    chunkSizeWarningLimit: 4096,
  },
  server: {
    port: 5199,
    strictPort: false,
  },
});
