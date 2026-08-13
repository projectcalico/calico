import { staticFlowLogs } from '../fixtures/flows';
import {
    expect,
    filterBar,
    flowLogRow,
    flowLogsTableWithHeader,
    gotoFlowLogs,
    openFilter,
    test,
    visibleTabPanel,
} from '../support/test';

/**
 * Screenshot baselines for the states a user actually looks at.
 *
 * Nothing else in this repo asserts anything about appearance. `src/theme`
 * (~2.2k lines) and the 550-odd CSS custom properties in `src/styles` are both
 * excluded from jest coverage, and the behavioural specs happily pass against a
 * component that works correctly and renders wrong. That matters right now
 * because the app is mid-migration from Chakra to Radix/shadcn/Tailwind: most of
 * these components are going to be rebuilt, and "it still behaves the same" is
 * only half the question.
 *
 * Scope is deliberately element-level wherever the state is local (the table,
 * a popover, the details panel) so an unrelated layout change does not invalidate
 * every baseline at once. Full-page shots are reserved for states that *are* the
 * whole page.
 *
 * Updating baselines: `yarn e2e:snapshots`. Review the diff image before
 * accepting it -- an unreviewed `--update-snapshots` is the visual equivalent of
 * `jest -u` and defeats the point of having baselines.
 */

test.describe('visual baselines', () => {
    test.describe('flow logs', () => {
        test.beforeEach(async ({ stub }) => {
            await stub.setBacklog(staticFlowLogs());
        });

        test('should match the populated table', async ({ page }) => {
            await gotoFlowLogs(page);
            await expect(flowLogRow(page, 'nginx-frontend')).toBeVisible();

            await expect(flowLogsTableWithHeader(page)).toHaveScreenshot(
                'table.png',
            );
        });

        test('should match an expanded row', async ({ page }) => {
            await gotoFlowLogs(page);
            await flowLogRow(page, 'nginx-frontend').click();

            // Anchored on the visible tab panel rather than by walking up from a
            // cell: a DOM nesting change would silently reframe the baseline
            // instead of failing.
            await expect(
                page.getByRole('rowheader', { name: 'packets_in' }),
            ).toBeAttached();

            await expect(visibleTabPanel(page)).toHaveScreenshot(
                'row-expanded.png',
            );
        });

        test('should match an expanded row on the JSON tab', async ({
            page,
        }) => {
            await gotoFlowLogs(page);
            await flowLogRow(page, 'nginx-frontend').click();
            await page.getByRole('tab', { name: 'JSON' }).click();

            await expect(visibleTabPanel(page)).toHaveScreenshot(
                'row-expanded-json.png',
            );
        });

        test('should match the column customiser', async ({ page }) => {
            await gotoFlowLogs(page);
            await expect(flowLogRow(page, 'nginx-frontend')).toBeVisible();

            // The customiser trigger is an icon-only button in the last column
            // header; its Chakra Tooltip does not give it an accessible name.
            await flowLogsTableWithHeader(page)
                .getByRole('columnheader')
                .last()
                .getByRole('button')
                .first()
                .click();

            await expect(page.getByRole('dialog')).toHaveScreenshot(
                'column-customiser.png',
            );
        });
    });

    test.describe('page states', () => {
        test('should match the empty state', async ({ page }) => {
            await gotoFlowLogs(page);
            await expect(page.getByTestId('empty-container')).toBeVisible();

            await expect(page).toHaveScreenshot('page-empty.png', {
                fullPage: true,
            });
        });

        test('should match the error state', async ({ page, stub }) => {
            await stub.fail({ flows: 500 });

            await gotoFlowLogs(page);
            await expect(
                page.getByRole('button', { name: 'Play' }),
            ).toBeVisible();

            await expect(page).toHaveScreenshot('page-error.png', {
                fullPage: true,
            });
        });
    });

    test.describe('filter bar', () => {
        test('should match the filter bar with nothing selected', async ({
            page,
        }) => {
            await gotoFlowLogs(page);
            await expect(
                page.getByRole('button', { name: 'Policy' }),
            ).toBeVisible();

            await expect(filterBar(page)).toHaveScreenshot('filter-bar.png');
        });

        test('should match the filter bar with filters applied', async ({
            page,
        }) => {
            // Active triggers carry badges, value labels and a clear button, all
            // of which are styling that only exists in this state.
            await gotoFlowLogs(
                page,
                '?source_namespace=web&source_namespace=jobs' +
                    '&dest_port=8443&protocol=tcp&action=deny&reporter=Src' +
                    '&start_time=15',
            );
            await expect(
                page.getByTestId('omnifilterlist-reset'),
            ).toBeVisible();

            await expect(filterBar(page)).toHaveScreenshot(
                'filter-bar-active.png',
            );
        });
    });

    test.describe('filter popovers', () => {
        // Every filter is a popover with its own list type, footer and empty
        // state. They are the densest styling in the app and the most likely to
        // be rebuilt, so each gets its own baseline.
        test('should match the source namespace filter', async ({
            page,
            stub,
        }) => {
            await stub.setHints({
                SourceNamespace: [
                    'web',
                    'jobs',
                    'backend',
                    'data',
                    'observability',
                ],
            });

            await gotoFlowLogs(page);
            const popover = await openFilter(page, 'Source Namespace');
            await expect(popover.getByText('observability')).toBeVisible();

            await expect(popover).toHaveScreenshot(
                'filter-source-namespace.png',
            );
        });

        test('should match a list filter with no options', async ({ page }) => {
            // The hint endpoint returns nothing, which is its own rendered state.
            await gotoFlowLogs(page);
            const popover = await openFilter(page, 'Destination');

            await expect(popover).toHaveScreenshot('filter-list-empty.png');
        });

        test('should match the policy filter', async ({ page }) => {
            await gotoFlowLogs(page);
            const popover = await openFilter(page, 'Policy');

            await expect(popover).toHaveScreenshot('filter-policy.png');
        });

        test('should match the action filter', async ({ page }) => {
            await gotoFlowLogs(page);
            const popover = await openFilter(page, 'Action');

            await expect(popover).toHaveScreenshot('filter-action.png');
        });

        test('should match the port filter', async ({ page }) => {
            await gotoFlowLogs(page);
            const popover = await openFilter(page, 'Port');

            await expect(popover).toHaveScreenshot('filter-port.png');
        });

        test('should match the start time filter', async ({ page }) => {
            await gotoFlowLogs(page);
            // The trigger folds its value into the label: "Start Time = Last 1
            // minute".
            const popover = await openFilter(page, /^Start Time/);

            await expect(popover).toHaveScreenshot('filter-start-time.png');
        });

        test('should match the reporter filter', async ({ page }) => {
            await gotoFlowLogs(page);
            const popover = await openFilter(page, 'Reporter');

            await expect(popover).toHaveScreenshot('filter-reporter.png');
        });
    });
});
