import meta from "./package.json" assert {type: "json"};
import nodeResolve from "@rollup/plugin-node-resolve";
import typescript from "@rollup/plugin-typescript";
import terser from "@rollup/plugin-terser";
import filesize from "rollup-plugin-filesize";

const extensions = ['.ts', '.js'];

const commonPlugins = [
    nodeResolve({ extensions }),
];

const config = {
    input: "./build/websdk.client.js",
    output: {
        file: `dist/${meta.name}.js`,
        name: "WebSdk",
        format: "umd",
        indent: true,
        extend: true,
        banner: `//maxzz ${meta.homepage} v${meta.version}`
    },
    plugins: [
        ...commonPlugins,
        terser(),
    ],
};

const configTs = {
    input: "./build/websdk.client.js",
    output: {
        file: `dist_min/${meta.name}.es.js`,
        name: "WebSdk",
        format: "es",
    },
    plugins: [
        ...commonPlugins,
        filesize({ showBeforeSizes: true, showGzippedSize: true }),
        terser(),
    ],
};

const configTsMin = {
    input: "./build/websdk.client.js",
    output: {
        file: `dist/${meta.name}.es.js`,
        name: "WebSdk",
        format: "es",
    },
    plugins: [
        ...commonPlugins,
    ],
};

const configTsDefs = {
    input: "./src/websdk.client.ts",
    output: {
        file: `dist_ts/${meta.name}.js`,
        name: "WebSdk",
        format: "es",
    },
    plugins: [
        ...commonPlugins,
        typescript({
            emitDeclarationOnly: true,
            declaration: true,
        })
    ],
};

export default [
    config,
    configTs,
    configTsMin,
    configTsDefs,
];
