import { aFlowLog } from '../fixtures/flows';
import { expect, flowLogRow, gotoFlowLogs, test } from '../support/test';

test.describe('error handling', () => {
    test('should offer a retry when the flows stream fails', async ({
        page,
        stub,
    }) => {
        await stub.fail({ flows: 500 });

        await gotoFlowLogs(page);

        // A failed stream surfaces as the table error plus a Play button to
        // retry, rather than an indefinite loading state.
        await expect(
            page.getByText('Could not display any flow logs at this time'),
        ).toBeVisible();
        await expect(page.getByRole('button', { name: 'Play' })).toBeVisible();
    });

    test('should recover once the backend comes back', async ({
        page,
        stub,
    }) => {
        await stub.fail({ flows: 500 });

        await gotoFlowLogs(page);
        await expect(page.getByRole('button', { name: 'Play' })).toBeVisible();

        await stub.fail({});
        await stub.setBacklog([aFlowLog({ source_name: 'recovered-flow' })]);

        await page.getByRole('button', { name: 'Play' }).click();

        await expect(flowLogRow(page, 'recovered-flow')).toBeVisible();
    });

    test('should still render flows when filter hints fail', async ({
        page,
        stub,
    }) => {
        // A broken filter-hints endpoint must not take the whole page down: the
        // flow stream is independent of it.
        await stub.fail({ hints: 500 });
        await stub.setBacklog([aFlowLog({ source_name: 'hints-broken' })]);

        await gotoFlowLogs(page);

        await expect(flowLogRow(page, 'hints-broken')).toBeVisible();
    });
});
