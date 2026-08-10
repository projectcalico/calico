import { flowName, manyFlowLogs } from '../fixtures/flows';
import {
    expect,
    flowLogRow,
    flowLogsTable,
    gotoFlowLogs,
    renderedFlowNames,
    scrollFlowLogs,
    scrollToFlowLogRow,
    test,
} from '../support/test';

/**
 * Volume is the condition this app actually runs in: a busy cluster streams
 * flows continuously and the table has to keep sorting, virtualising and
 * rendering while they arrive. The rest of the suite uses a handful of flows,
 * which never exercises the throttled buffer in `useStream` or the
 * `react-window` list in `DataTable`.
 *
 * The index in a flow's name is also its position in time (`manyFlowLogs`
 * spaces them out), so "newest first" is checkable by reading the rendered
 * names off the screen.
 */

const BACKLOG_SIZE = 500;
const STREAM_BATCHES = 10;
const STREAM_BATCH_SIZE = 25;
const STREAMED = STREAM_BATCHES * STREAM_BATCH_SIZE;

/** Splits a generated array of flows into equal batches to emit in order. */
const inBatches = <T>(flows: T[], size: number): T[][] =>
    Array.from({ length: Math.ceil(flows.length / size) }, (_, batch) =>
        flows.slice(batch * size, batch * size + size),
    );

const indexOf = (name: string) => Number(name.split('-')[1]);

test.describe('high volume flow logs', () => {
    test('should render a large backlog newest first', async ({
        page,
        stub,
    }) => {
        await stub.setBacklog(manyFlowLogs(BACKLOG_SIZE));

        await gotoFlowLogs(page);

        await expect(flowLogsTable(page)).toBeVisible();
        // The table sorts by start_time descending by default, so the last flow
        // the backend sent is the first row.
        await expect(
            flowLogRow(page, flowName(BACKLOG_SIZE - 1)),
        ).toBeVisible();

        const names = await renderedFlowNames(page);
        expect(names[0]).toBe(flowName(BACKLOG_SIZE - 1));

        // Descending, with no gaps: a row dropped or transposed by the sort
        // would show up here even though every row on its own looks fine.
        expect(names).toEqual(
            names.map((_, offset) => flowName(BACKLOG_SIZE - 1 - offset)),
        );
    });

    test('should keep the backlog virtualised rather than rendering every row', async ({
        page,
        stub,
    }) => {
        await stub.setBacklog(manyFlowLogs(BACKLOG_SIZE));

        await gotoFlowLogs(page);
        await expect(
            flowLogRow(page, flowName(BACKLOG_SIZE - 1)),
        ).toBeVisible();

        // Only the rows on screen (plus react-window's overscan) are in the
        // DOM. Losing virtualisation would put 500 rows in the document and the
        // page would crawl on a real cluster, so pin it.
        const rendered = await renderedFlowNames(page);
        expect(rendered.length).toBeGreaterThan(5);
        expect(rendered.length).toBeLessThan(BACKLOG_SIZE / 2);
    });

    test('should scroll a large backlog down to the oldest flow', async ({
        page,
        stub,
    }) => {
        await stub.setBacklog(manyFlowLogs(BACKLOG_SIZE));

        await gotoFlowLogs(page);
        await expect(
            flowLogRow(page, flowName(BACKLOG_SIZE - 1)),
        ).toBeVisible();

        // Every flow is reachable, not just the screenful the table starts on:
        // the oldest sits at the very bottom of the sorted list.
        const oldest = await scrollToFlowLogRow(page, flowName(0));

        await expect(oldest).toBeVisible();
    });

    test('should keep up with flows streaming in continuously', async ({
        page,
        stub,
    }) => {
        const pageErrors: Error[] = [];
        page.on('pageerror', (error) => pageErrors.push(error));

        // Generated as one array so timestamps increase across batches as well
        // as within them.
        const batches = inBatches(manyFlowLogs(STREAMED), STREAM_BATCH_SIZE);

        await gotoFlowLogs(page);
        await expect(page.getByText('Waiting for flows')).toBeVisible();

        for (const batch of batches) {
            await stub.emit(batch);
            // Paced so the batches land in separate STREAM_THROTTLE windows,
            // i.e. as a series of appends rather than one bulk render.
            await page.waitForTimeout(400);
        }

        // The newest flow of the last batch tops the table, so the append path
        // both kept its ordering and kept rendering to the end of the flood.
        const newest = flowName(STREAMED - 1);
        await expect(flowLogRow(page, newest)).toBeVisible();
        await expect
            .poll(async () => (await renderedFlowNames(page))[0])
            .toBe(newest);

        // Nothing from the first batch was dropped on the way.
        await expect(await scrollToFlowLogRow(page, flowName(0))).toBeVisible();

        expect(pageErrors).toEqual([]);
    });

    test('should still show every row when a burst arrives at once', async ({
        page,
        stub,
    }) => {
        await gotoFlowLogs(page);
        await expect(page.getByText('Waiting for flows')).toBeVisible();

        // One emit, no pacing: the whole burst lands inside a single throttle
        // window and is committed to the table as one batch.
        await stub.emit(manyFlowLogs(BACKLOG_SIZE));

        await expect(
            flowLogRow(page, flowName(BACKLOG_SIZE - 1)),
        ).toBeVisible();
        await expect(await scrollToFlowLogRow(page, flowName(0))).toBeVisible();
    });

    test('should still expand a row after a flood of flows', async ({
        page,
        stub,
    }) => {
        await stub.setBacklog(manyFlowLogs(BACKLOG_SIZE, { packets_in: '77' }));

        await gotoFlowLogs(page);

        // Scrolled away from the top, so the row being expanded is one the
        // virtualised list mounted during scrolling rather than on first paint.
        await scrollFlowLogs(page, 4_000);
        await expect
            .poll(async () => (await renderedFlowNames(page))[0])
            .not.toBe(flowName(BACKLOG_SIZE - 1));

        // Taken from what the list actually mounted, rather than from an index
        // that assumes a row height.
        const onScreen = await renderedFlowNames(page);
        const row = flowLogRow(page, onScreen[Math.floor(onScreen.length / 2)]);
        await expect(row).toBeVisible();
        await row.click();

        await expect(
            page.getByRole('rowheader', { name: 'packets_in' }),
        ).toBeVisible();
        await expect(page.getByText('Flows stream paused')).toBeVisible();
    });

    test('should hold the sort order while flows keep arriving', async ({
        page,
        stub,
    }) => {
        const flows = manyFlowLogs(STREAMED);

        await stub.setBacklog(flows.slice(0, STREAM_BATCH_SIZE));
        await gotoFlowLogs(page);
        await expect(
            flowLogRow(page, flowName(STREAM_BATCH_SIZE - 1)),
        ).toBeVisible();

        for (const batch of inBatches(
            flows.slice(STREAM_BATCH_SIZE),
            STREAM_BATCH_SIZE,
        )) {
            await stub.emit(batch);
            await page.waitForTimeout(400);
        }

        await expect(flowLogRow(page, flowName(STREAMED - 1))).toBeVisible();

        // Newly streamed flows are prepended to the list the table sorts, so a
        // sort that stopped being applied would interleave the batches here.
        const names = await renderedFlowNames(page);
        const indexes = names.map(indexOf);
        expect(indexes).toEqual([...indexes].sort((a, b) => b - a));
        expect(indexes[0]).toBe(STREAMED - 1);
    });
});
