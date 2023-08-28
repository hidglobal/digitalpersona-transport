// @ts-check
import nodeResolve from "@rollup/plugin-node-resolve";
import typescript from "@rollup/plugin-typescript";
import terser from "@rollup/plugin-terser";
import filesize from "rollup-plugin-filesize";
import meta from "./package.json" assert {type: "json"};

const extensions = ['.ts', '.js'];

const commonPlugins = [
    nodeResolve({ extensions }),
];

function configUmd({ input, output, minify }) {
    return {
        input,
        output: {
            file: output,
            name: "WebSdk",
            format: "umd",
            indent: true,
            extend: true,
            banner: `//maxzz ${meta.homepage} v${meta.version}`
        },
        plugins: [
            ...commonPlugins,
            minify ? terser() : [],
        ],
    };
}

function configTsMin({ input, output }) {
    return {
        input,
        output: {
            file: output,
            name: "WebSdk",
            format: "es",
        },
        plugins: [
            ...commonPlugins,
            filesize({ showBeforeSizes: "build", showGzippedSize: true }),
            terser(),
        ],
    };
}

function configTs({ input, output }) {
    return {
        input,
        output: {
            file: output,
            name: "WebSdk",
            format: "es",
        },
        plugins: [
            ...commonPlugins,
        ],
    };
}

function configTsDefs({ input, output }) {
    return {
        input,
        output: {
            file: output,
            name: "WebSdk",
            format: "es",
        },
        plugins: [
            ...commonPlugins,
            typescript({ emitDeclarationOnly: true, declaration: true, })
        ],
    };
}

const scrFromBuild = "./build/websdk.client.js";
const scrFromTs = "./src/websdk.client.ts";

export default [
    configUmd({ input: scrFromBuild, output: `dist/umd/websdk.client.js`, minify: false }),
    configUmd({ input: scrFromBuild, output: `dist/umd/websdk.client.min.js`, minify: true }),
    configTsMin({ input: scrFromBuild, output: `dist/index.es.min.js` }),
    configTs({ input: scrFromBuild, output: `dist/index.js` }),
    configTsDefs({ input: scrFromTs, output: `dist/index.js` }),
];
