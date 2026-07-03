import { defineConfig } from "@rslib/core";

export default defineConfig({
  lib: [
    {
      format: "esm",
      syntax: "es2022",
      bundle: true,
      dts: true
    }
  ],
  source: {
    entry: {
      index: "./src/index.ts"
    }
  },
  output: {
    target: "node",
    minify: {
      js: true,
      jsOptions: {
        minimizerOptions: {
          mangle: true,
          compress: true,
          format: {
            comments: false
          }
        }
      }
    }
  }
});
