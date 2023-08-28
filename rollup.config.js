// @ts-check
import { readFileSync } from 'node:fs';
import nodeResolve from "@rollup/plugin-node-resolve";
import typescript from "@rollup/plugin-typescript";
import terser from "@rollup/plugin-terser";
import filesize from "rollup-plugin-filesize";
import dts from "rollup-plugin-dts";

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url)).toString());

function makeUmd({ input, output, minify }) {
    return {
        input,
        output: {
            file: output,
            name: "WebSdk",
            format: "umd",
            indent: true,
            extend: true,
            banner: `// Package: ${pkg.name}\n// Homepage: ${pkg.homepage}\n// Version: v${pkg.version}\n`,
        },
        plugins: [
            nodeResolve(),
            typescript({ outDir: "dist/umd", declaration: false }),
            minify ? terser() : [],
            minify ? filesize({ showBeforeSizes: "build", showGzippedSize: true }) : [],
        ],
    };
}

function makeEs({ input, output }) {
    return {
        input,
        output: {
            file: output,
            name: "WebSdk",
            format: "es",
        },
        plugins: [
            nodeResolve(),
            typescript({ outDir: "dist", declarationDir: "dist/types", declaration: true }),
        ],
    };
}

function makeDts({ input, output }) {
    return {
        input: "dist/types/index.d.ts",
        output: {
            file: "dist/index.d.ts",
            format: "es",
        },
        plugins: [
            // nodeResolve(),
            // typescript({ outDir: "dist", declarationDir: "dist/types", declaration: true }),
            dts(),
        ],
    };
}

const scrFromTs = "src/index.ts";

export default [
    makeUmd({ input: scrFromTs, output: `dist/umd/websdk.client.min.js`, minify: true }),
    makeUmd({ input: scrFromTs, output: `dist/umd/websdk.client.js`, minify: false }),
    makeEs({ input: scrFromTs, output: `dist/index.js` }),
    // makeDts({ input: scrFromTs, output: `dist/index.js` }),
];
