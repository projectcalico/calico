import { aFlowLog } from '../fixtures/flows';
import { expect, flowLogRow, gotoFlowLogs, test } from '../support/test';

test.describe('stream controls', () => {
    test('should show the waiting indicator before any flow arrives', async ({
        page,
    }) => {
        await gotoFlowLogs(page);

        await expect(page.getByText('Waiting for flows')).toBeVisible();
    });

    test('should pause and resume the stream', async ({ page, stub }) => {
        await stub.setBacklog([aFlowLog({ source_name: 'before-pause' })]);

        await gotoFlowLogs(page);
        await expect(flowLogRow(page, 'before-pause')).toBeVisible();

        const pause = page.getByRole('button', { name: 'Pause' });
        await expect(pause).toBeVisible();
        await pause.click();

        // Pausing closes the stream server-side.
        await expect.poll(async () => (await stub.streams()).open).toBe(0);

        const play = page.getByRole('button', { name: 'Play' });
        await expect(play).toBeVisible();
        await play.click();

        // Resuming opens a fresh stream.
        await expect.poll(async () => (await stub.streams()).open).toBe(1);
        await expect(pause).toBeVisible();
    });

    test('should not lose already-streamed flows while paused', async ({
        page,
        stub,
    }) => {
        await stub.setBacklog([aFlowLog({ source_name: 'kept-flow' })]);

        await gotoFlowLogs(page);
        await expect(flowLogRow(page, 'kept-flow')).toBeVisible();

        await page.getByRole('button', { name: 'Pause' }).click();

        await expect(flowLogRow(page, 'kept-flow')).toBeVisible();
    });

    test('should pause the stream when a row is expanded', async ({
        page,
        stub,
    }) => {
        await stub.setBacklog([aFlowLog({ source_name: 'expand-me' })]);

        await gotoFlowLogs(page);
        await flowLogRow(page, 'expand-me').click();

        // Expanding a row stops the stream so the details do not shift around.
        await expect(page.getByText('Flows stream paused')).toBeVisible();
        await expect.poll(async () => (await stub.streams()).open).toBe(0);
    });
});
