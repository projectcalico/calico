import { aFlowLog, someFlowLogs } from '../fixtures/flows';
import { expect, flowLogRow, gotoFlowLogs, test } from '../support/test';

test.describe('omni filters', () => {
    test('should put a chosen filter in the URL', async ({ page, stub }) => {
        await stub.setHints({
            SourceNamespace: ['web', 'jobs', 'observability'],
        });
        await stub.setBacklog(someFlowLogs());

        await gotoFlowLogs(page);

        await page.getByRole('button', { name: 'Source Namespace' }).click();
        await page
            .getByTestId('omni-filter-popover-content')
            .getByText('jobs', { exact: true })
            .click();

        await expect(page).toHaveURL(/source_namespace=jobs/);
    });

    test('should restore filter state from a deep link', async ({
        page,
        stub,
    }) => {
        await stub.setHints({
            SourceNamespace: ['web', 'jobs', 'observability'],
        });

        await gotoFlowLogs(page, '?source_namespace=jobs&action=deny');

        // The triggers reflect the restored selection without the user
        // reopening the filters. List filters name their selection; the action
        // filter shows a count badge instead.
        await expect(
            page.getByRole('button', { name: /Source Namespace/ }),
        ).toContainText('jobs');
        await expect(
            page.getByTestId('action-omni-filter-button-trigger'),
        ).toContainText('1');
    });

    test('should restore a port and protocol deep link', async ({ page }) => {
        await gotoFlowLogs(page, '?dest_port=8080&protocol=tcp');

        // The port filter renders the pair as PROTOCOL:PORT, uppercased.
        await expect(page.getByTestId('port-filter-button-trigger')).toHaveText(
            'Port = TCP:8080',
        );
    });

    test('should restore a start time deep link', async ({ page }) => {
        await gotoFlowLogs(page, '?start_time=15');

        await expect(
            page.getByRole('button', { name: /Start Time/ }),
        ).toContainText('15');
    });

    test('should clear every filter when reset is used', async ({
        page,
        stub,
    }) => {
        await stub.setHints({ SourceNamespace: ['web', 'jobs'] });

        await gotoFlowLogs(
            page,
            '?source_namespace=jobs&action=deny&dest_port=8080',
        );

        await page.getByTestId('omnifilterlist-reset').click();

        await expect(page).not.toHaveURL(/source_namespace/);
        await expect(page).not.toHaveURL(/action/);
        await expect(page).not.toHaveURL(/dest_port/);
    });

    test('should keep unrelated search params when filters change', async ({
        page,
        stub,
    }) => {
        await stub.setHints({ SourceNamespace: ['web', 'jobs'] });

        await gotoFlowLogs(page, '?ref=docs');

        await page.getByRole('button', { name: 'Source Namespace' }).click();
        await page
            .getByTestId('omni-filter-popover-content')
            .getByText('jobs', { exact: true })
            .click();

        await expect(page).toHaveURL(/ref=docs/);
        await expect(page).toHaveURL(/source_namespace=jobs/);
    });

    test('should replace the visible flows when filters change', async ({
        page,
        stub,
    }) => {
        await stub.setBacklog([aFlowLog({ source_name: 'unfiltered-flow' })]);
        await stub.setHints({ SourceNamespace: ['web', 'jobs'] });

        await gotoFlowLogs(page);
        await expect(flowLogRow(page, 'unfiltered-flow')).toBeVisible();

        // The next stream returns a different flow, as a real filtered stream
        // would.
        await stub.setBacklog([aFlowLog({ source_name: 'filtered-flow' })]);

        await page.getByRole('button', { name: 'Source Namespace' }).click();
        await page
            .getByTestId('omni-filter-popover-content')
            .getByText('jobs', { exact: true })
            .click();

        await expect(flowLogRow(page, 'filtered-flow')).toBeVisible();
        // Flows from the previous, unfiltered stream must not linger.
        await expect(flowLogRow(page, 'unfiltered-flow')).toBeHidden();
    });
});
