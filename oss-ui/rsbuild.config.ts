import { defineConfig } from '@rsbuild/core';
import { pluginReact } from '@rsbuild/plugin-react';
import { pluginTypeCheck } from '@rsbuild/plugin-type-check';

export default defineConfig({
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
    },
});
