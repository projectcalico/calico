import { defineConfig, loadEnv, rspack } from '@rsbuild/core';
import { pluginReact } from '@rsbuild/plugin-react';
import { pluginTypeCheck } from '@rsbuild/plugin-type-check';

const { publicVars } = loadEnv({ prefixes: ['APP_'] });

export default defineConfig({
    tools: {
        rspack: {
            plugins: [
                new rspack.CopyRspackPlugin({
                    patterns: [
                        {
                            from: 'public/favicon.ico',
                            to: 'public/favicon.ico',
                        },
                    ],
                }),
            ],
        },
    },
    plugins: [pluginReact(), pluginTypeCheck()],
    server: {
        port: 3000,
    },
    html: {
        template: './index.html',
    },
    source: {
        entry: {
            index: './src/main.tsx',
        },
        define: publicVars,
    },
});
