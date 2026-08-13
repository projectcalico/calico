import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig, devices } from '@playwright/test';

// package.json sets "type": "module", so this config is loaded as ESM.
const e2eDir = path.dirname(fileURLToPath(import.meta.url));
const whiskerRoot = path.join(e2eDir, '..');

const APP_PORT = Number(process.env.E2E_APP_PORT ?? 3000);
const STUB_PORT = Number(process.env.E2E_STUB_PORT ?? 8081);

/**
 * The app reads its API URL from .env at build time (APP_API_URL, which points
 * at http://localhost:8081/whisker-backend by default), so the stub has to
 * listen on that port and path prefix rather than being injected at runtime.
 */
export default defineConfig({
    testDir: './tests',
    outputDir: path.join(whiskerRoot, 'e2e-results'),

    // useStream buffers incoming flows for a second before committing them to
    // state, so assertions here legitimately wait longer than on a static page.
    timeout: 60_000,
    expect: {
        timeout: 15_000,
        toHaveScreenshot: {
            // CSS animations are frozen to their end state (Chakra's Skeleton
            // pulse would otherwise never settle). toHaveScreenshot also retries
            // until two consecutive captures agree, which covers the
            // framer-motion row transitions that CSS freezing cannot stop.
            animations: 'disabled',
            caret: 'hide',
            scale: 'css',
            // Hides dev-only chrome; see the file for what and why.
            stylePath: path.join(e2eDir, 'screenshot.css'),
            // Tolerance for antialiasing jitter between runs on one platform.
            // Baselines are per-platform, so this is not covering for OS
            // differences -- see the note in playwright.config's snapshot path.
            maxDiffPixelRatio: 0.01,
        },
    },

    /**
     * Baselines are specific to the OS *and* the architecture: font
     * rasterisation differs between macOS and the Linux container CI runs in, and
     * Playwright's {platform} token is only `linux`, so an arm64 set generated on
     * a laptop would silently overwrite the amd64 set CI compares against.
     * Including the arch keeps darwin-arm64, linux-x64 and linux-arm64 apart.
     */
    snapshotPathTemplate: `{testDir}/__screenshots__/{platform}-${process.arch}/{testFileName}/{arg}{ext}`,

    // The stub backend is a single shared process that records requests, so
    // tests must not overlap.
    fullyParallel: false,
    workers: 1,

    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 1 : 0,

    reporter: process.env.CI
        ? [
              ['list'],
              [
                  'html',
                  {
                      open: 'never',
                      outputFolder: path.join(whiskerRoot, 'e2e-report'),
                  },
              ],
          ]
        : [['list']],

    use: {
        baseURL: `http://localhost:${APP_PORT}`,
        trace: 'retain-on-failure',
        screenshot: 'only-on-failure',
        video: 'retain-on-failure',
        // Big enough that the virtualised table renders a useful number of rows.
        viewport: { width: 1440, height: 900 },
        // The table renders times with toLocaleTimeString(), so both of these
        // have to be pinned or timestamps differ by machine. Required for the
        // visual baselines; harmless for the rest of the suite.
        locale: 'en-US',
        timezoneId: 'UTC',
    },

    projects: [
        {
            name: 'chromium',
            use: { ...devices['Desktop Chrome'] },
        },
    ],

    webServer: [
        {
            command: 'node e2e/stub/server.mjs',
            cwd: whiskerRoot,
            url: `http://localhost:${STUB_PORT}/__stub__/health`,
            reuseExistingServer: !process.env.CI,
            stdout: 'pipe',
            stderr: 'pipe',
        },
        {
            command: 'yarn start',
            cwd: whiskerRoot,
            url: `http://localhost:${APP_PORT}`,
            reuseExistingServer: !process.env.CI,
            timeout: 180_000,
            stdout: 'pipe',
            stderr: 'pipe',
        },
    ],
});
