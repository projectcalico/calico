import { test as base, expect, Page } from '@playwright/test';
import { StubBackend } from './stub';

/**
 * The Playwright fixtures every Whisker spec should import from.
 *
 * Two things happen automatically for each test:
 *  - the stub backend is reset, so tests never see each other's flows
 *  - the app is sealed off from the internet: /config.json is served from the
 *    fixture below and any request to a non-local host is aborted, so a test can
 *    never depend on (or be slowed by) the real Calico Cloud endpoints
 */

/**
 * Stands in for public/config.json. Notifications are disabled so the promotions
 * banner never renders and never calls out to calico_cloud_url.
 */
export const APP_CONFIG = {
    config: {
        cluster_id: 'e2e-cluster-id',
        cluster_type: 'e2e',
        calico_version: 'e2e',
        notifications: 'Disabled',
        calico_cloud_url: 'http://localhost:9/not-used',
    },
    features: {},
};

const isLocal = (url: string) => {
    const { hostname } = new URL(url);

    return hostname === 'localhost' || hostname === '127.0.0.1';
};

type Fixtures = {
    stub: StubBackend;
    sealed: void;
};

export const test = base.extend<Fixtures>({
    stub: async ({}, use) => {
        const stub = new StubBackend();
        await stub.reset();

        await use(stub);

        await stub.reset();
    },

    sealed: [
        async ({ page }, use) => {
            await page.route('**/config.json', (route) =>
                route.fulfill({ json: APP_CONFIG }),
            );

            // Registered last, so it sees every request first and defers local
            // ones to the handler above (or to the network).
            await page.route('**/*', (route) => {
                const url = route.request().url();

                if (isLocal(url)) {
                    return route.fallback();
                }

                console.warn(`[e2e] blocked external request to ${url}`);

                return route.abort();
            });

            await use();
        },
        { auto: true },
    ],
});

export { expect };

/** Navigates to the flow logs page, optionally with filter search params. */
export const gotoFlowLogs = (page: Page, search = '') =>
    page.goto(`/flow-logs${search}`);

/**
 * The flow logs table body.
 *
 * Note this element holds the data rows only -- DataTable renders the column
 * headers as siblings, one level up. Use `flowLogsTableWithHeader` when the
 * headers matter.
 */
export const flowLogsTable = (page: Page) =>
    page.getByTestId('flow-logs-table');

/** The whole table: column headers plus body. */
export const flowLogsTableWithHeader = (page: Page) =>
    flowLogsTable(page).locator('..');

/**
 * The tab panel currently on screen.
 *
 * Chakra keeps non-selected panels mounted but hidden, so an index would pick
 * the wrong one; filtering on visibility gets the active panel either way.
 */
export const visibleTabPanel = (page: Page) =>
    page.getByRole('tabpanel').filter({ visible: true });

/**
 * The row of filter triggers above the table.
 *
 * Anchored on the list's own testid rather than by walking up from the first
 * trigger: the parent chain has already changed once (the page used to wrap the
 * list in a Flex of its own), and walking up silently reframed the baseline to
 * include the stream status beside it instead of failing on the locator.
 */
export const filterBar = (page: Page) => page.getByTestId('table-filters');

/**
 * Opens the named filter and returns its popover.
 *
 * The five filters do not share a testid convention -- only ActionOmniFilter and
 * the library OmniFilter set one -- but all of them render a Chakra
 * PopoverContent, and only one can be open at a time, so the dialog role is the
 * one locator that works for all of them.
 */
export const openFilter = async (page: Page, name: string | RegExp) => {
    // Exact by default, because "Source" would otherwise also match "Source
    // Namespace". Triggers that fold their value into the label (Start Time
    // renders "Start Time = Last 1 minute") need a RegExp instead.
    await page.getByRole('button', { name, exact: true }).click();

    const popover = page.getByRole('dialog');
    await popover.waitFor();

    return popover;
};

/** A flow logs row, located by any distinctive cell text it contains. */
export const flowLogRow = (page: Page, text: string) =>
    flowLogsTable(page).getByRole('row').filter({ hasText: text });

/**
 * The `manyFlowLogs` source names currently rendered, top row first.
 *
 * The table is virtualised, so this is the window of rows on screen rather than
 * everything the app is holding. Rows carry a dest name too, hence the prefix
 * match rather than reading the whole row.
 */
export const renderedFlowNames = async (page: Page, prefix = 'flow') => {
    const name = new RegExp(`${prefix}-\\d+`);
    const rows = await flowLogsTable(page).getByRole('row').allTextContents();

    return rows
        .map((row) => row.match(name)?.[0])
        .filter((match): match is string => match !== undefined);
};

/**
 * Wheels the virtualised list down by `pixels`, over the middle of the table so
 * the list scrolls rather than the page.
 */
export const scrollFlowLogs = async (page: Page, pixels: number) => {
    const box = await flowLogsTable(page).boundingBox();
    const viewport = page.viewportSize();

    if (!box || !viewport) {
        throw new Error('flow logs table is not on screen');
    }

    await page.mouse.move(
        box.x + box.width / 2,
        Math.min(box.y + box.height / 2, viewport.height - 10),
    );
    await page.mouse.wheel(0, pixels);
};

/**
 * Scrolls until the row containing `text` is rendered, and returns it.
 *
 * Rows below the fold are not in the DOM at all, so a locator for one of them
 * finds nothing until the list has been scrolled to it. Gives up after
 * `maxScrolls` and returns the (empty) locator, so the caller's expect reports
 * the failure rather than this helper throwing something less informative.
 */
export const scrollToFlowLogRow = async (
    page: Page,
    text: string,
    { step = 2_000, maxScrolls = 40 } = {},
) => {
    const row = flowLogRow(page, text);

    for (let scrolls = 0; scrolls < maxScrolls; scrolls++) {
        if ((await row.count()) > 0) {
            break;
        }

        await scrollFlowLogs(page, step);
    }

    return row;
};
