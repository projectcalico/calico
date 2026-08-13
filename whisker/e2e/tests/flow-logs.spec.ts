import { aFlowLog, aPolicy, someFlowLogs, StubPolicy } from '../fixtures/flows';
import {
    expect,
    flowLogRow,
    flowLogsTable,
    gotoFlowLogs,
    test,
} from '../support/test';

test.describe('flow logs table', () => {
    test('should render the flows the backend streams', async ({
        page,
        stub,
    }) => {
        await stub.setBacklog(someFlowLogs());

        await gotoFlowLogs(page);

        await expect(flowLogsTable(page)).toBeVisible();
        await expect(flowLogRow(page, 'nginx-frontend')).toBeVisible();
        await expect(flowLogRow(page, 'batch-runner')).toBeVisible();
        await expect(flowLogRow(page, 'metrics-agent')).toBeVisible();
    });

    test('should render every cell of a flow', async ({ page, stub }) => {
        await stub.setBacklog([
            aFlowLog({
                source_name: 'checkout-api',
                source_namespace: 'shop',
                dest_name: 'payments',
                dest_namespace: 'billing',
                protocol: 'tcp',
                dest_port: '8443',
                reporter: 'Src',
            }),
        ]);

        await gotoFlowLogs(page);

        const row = flowLogRow(page, 'checkout-api');
        await expect(row).toBeVisible();

        for (const cell of ['shop', 'payments', 'billing', 'tcp', '8443']) {
            await expect(row).toContainText(cell);
        }
    });

    test('should show the empty state until flows arrive', async ({
        page,
        stub,
    }) => {
        await gotoFlowLogs(page);

        await expect(page.getByTestId('empty-container')).toBeVisible();
        await expect(page.getByText('Nothing to see yet.')).toBeVisible();
        await expect(
            page.getByText('Flows will start to appear shortly.'),
        ).toBeVisible();

        // A flow arriving on the open stream replaces the empty state.
        await stub.emit([aFlowLog({ source_name: 'late-arrival' })]);

        await expect(flowLogRow(page, 'late-arrival')).toBeVisible();
        await expect(page.getByTestId('empty-container')).toBeHidden();
    });

    test('should append flows that arrive while the page is open', async ({
        page,
        stub,
    }) => {
        await stub.setBacklog([aFlowLog({ source_name: 'first-flow' })]);

        await gotoFlowLogs(page);
        await expect(flowLogRow(page, 'first-flow')).toBeVisible();

        await stub.emit([aFlowLog({ source_name: 'second-flow' })]);

        await expect(flowLogRow(page, 'second-flow')).toBeVisible();
        // The earlier flow must still be there: the stream appends, it does not
        // replace, unless the filters changed.
        await expect(flowLogRow(page, 'first-flow')).toBeVisible();
    });

    test('should tell the user the filters are the reason nothing matched', async ({
        page,
    }) => {
        await gotoFlowLogs(page, '?action=deny');

        await expect(
            page.getByText('flows that match the active filters', {
                exact: false,
            }),
        ).toBeVisible();
    });

    test('should open flow details when a row is clicked', async ({
        page,
        stub,
    }) => {
        await stub.setBacklog([
            aFlowLog({ source_name: 'inspect-me', packets_in: '4321' }),
        ]);

        await gotoFlowLogs(page);

        await flowLogRow(page, 'inspect-me').click();

        // The details view lists the raw flow fields that the table omits.
        // Scoped by role because the JSON tab renders the same keys again.
        await expect(
            page.getByRole('rowheader', { name: 'packets_in' }),
        ).toBeVisible();
        await expect(
            page.getByRole('cell', { name: '4321', exact: true }).first(),
        ).toBeVisible();
        await expect(page.getByRole('tab', { name: 'JSON' })).toBeVisible();
        await expect(
            page.getByTestId('enforced-policies-table').first(),
        ).toBeVisible();
    });

    // KNOWN DEFECT, pinned with test.fail so CI stays green but this starts
    // failing (i.e. demands attention) the moment it is fixed.
    //
    // whisker-backend serializes PolicyTrace.Pending with no omitempty, so a
    // flow with no pending policies arrives as `"pending": null`.
    // transformPolicyLog in PoliciesLogDetails calls .map on it unguarded, so
    // expanding that row throws and the error boundary blanks the whole page.
    test.fail(
        'should expand a flow whose pending policy trace is null',
        async ({ page, stub }) => {
            await stub.setBacklog([
                aFlowLog({
                    source_name: 'no-pending-policies',
                    policies: {
                        enforced: [aPolicy()],
                        pending: null as unknown as StubPolicy[],
                    },
                }),
            ]);

            await gotoFlowLogs(page);
            await flowLogRow(page, 'no-pending-policies').click();

            // Short timeout: this assertion is expected to fail, so the default
            // would just burn 15s on every run.
            await expect(
                page.getByRole('rowheader', { name: 'packets_in' }),
            ).toBeVisible({ timeout: 3_000 });
        },
    );
});
