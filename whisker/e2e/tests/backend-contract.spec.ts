import { someFlowLogs } from '../fixtures/flows';
import { expect, gotoFlowLogs, test } from '../support/test';

/**
 * These specs assert what the frontend asks whisker-backend for. Component
 * tests cannot cover this: they mock the api layer out, so a refactor can change
 * the request the app makes without any of them noticing. A wrong `filters`
 * blob shows the user an empty table rather than an error, which is exactly the
 * kind of regression that ships.
 */
test.describe('backend request contract', () => {
    test('should open one flows stream on load', async ({ page, stub }) => {
        await gotoFlowLogs(page);

        await expect
            .poll(async () => (await stub.streamRequests()).length)
            .toBe(1);

        const [request] = await stub.streamRequests();
        expect(request.filters).toEqual({});
        // Default lookback is one minute, expressed in negative seconds.
        expect(request.startTimeGte).toBe('-60');
    });

    test.describe('deep links', () => {
        const cases: Array<{
            name: string;
            search: string;
            filters: Record<string, unknown>;
        }> = [
            {
                name: 'a source namespace',
                search: '?source_namespace=jobs',
                filters: {
                    source_namespaces: [{ type: 'Exact', value: 'jobs' }],
                },
            },
            {
                name: 'several values for one filter',
                search: '?dest_namespace=billing&dest_namespace=shop',
                filters: {
                    dest_namespaces: [
                        { type: 'Exact', value: 'billing' },
                        { type: 'Exact', value: 'shop' },
                    ],
                },
            },
            {
                name: 'a port and protocol',
                search: '?dest_port=8443&protocol=tcp',
                filters: {
                    dest_ports: [{ type: 'Exact', value: 8443 }],
                    protocols: [{ type: 'Exact', value: 'tcp' }],
                },
            },
            {
                name: 'an action',
                search: '?action=deny',
                filters: { actions: ['deny'] },
            },
            {
                name: 'a reporter',
                search: '?reporter=Dst',
                filters: { reporter: 'Dst' },
            },
            {
                name: 'a policy',
                search: `?policy=${encodeURIComponent(
                    JSON.stringify([
                        { kind: 'CalicoNetworkPolicy', name: 'allow-nginx' },
                    ]),
                )}`,
                filters: {
                    policies: [
                        {
                            name: { type: 'Exact', value: 'allow-nginx' },
                            kind: 'CalicoNetworkPolicy',
                        },
                    ],
                },
            },
        ];

        for (const { name, search, filters } of cases) {
            test(`should turn ${name} into a backend filter`, async ({
                page,
                stub,
            }) => {
                await gotoFlowLogs(page, search);

                await expect
                    .poll(async () => await stub.lastStreamFilters())
                    .toEqual(filters);
            });
        }
    });

    test('should request the start time as a lookback, not a filter', async ({
        page,
        stub,
    }) => {
        await gotoFlowLogs(page, '?start_time=15');

        await expect
            .poll(
                async () => (await stub.streamRequests()).at(-1)?.startTimeGte,
            )
            .toBe('-900');

        expect(await stub.lastStreamFilters()).toEqual({});
    });

    test('should restart the stream when a filter changes', async ({
        page,
        stub,
    }) => {
        await stub.setHints({ SourceNamespace: ['web', 'jobs'] });
        await stub.setBacklog(someFlowLogs());

        await gotoFlowLogs(page);
        await expect.poll(async () => (await stub.streams()).opened).toBe(1);

        await page.getByRole('button', { name: 'Source Namespace' }).click();
        await page
            .getByTestId('omni-filter-popover-content')
            .getByText('jobs', { exact: true })
            .click();

        // A second stream is opened, carrying the new filter.
        await expect
            .poll(async () => (await stub.streams()).opened)
            .toBeGreaterThan(1);
        await expect
            .poll(async () => await stub.lastStreamFilters())
            .toEqual({
                source_namespaces: [{ type: 'Exact', value: 'jobs' }],
            });
    });

    test('should not constrain a filter list by its own selection', async ({
        page,
        stub,
    }) => {
        // Opening Source Namespace with a destination filter already applied
        // must send the destination filter but must not send the source
        // namespaces, or the user could never widen their selection.
        await stub.setHints({ SourceNamespace: ['web', 'jobs'] });

        await gotoFlowLogs(
            page,
            '?source_namespace=web&dest_namespace=billing',
        );

        await page.getByRole('button', { name: 'Source Namespace' }).click();

        await expect
            .poll(async () => {
                const requests = await stub.hintRequests();

                return requests.find(
                    (request) => request.type === 'SourceNamespace',
                )?.filters;
            })
            .toEqual({
                dest_namespaces: [{ type: 'Exact', value: 'billing' }],
            });
    });

    test('should not call out to any external host', async ({ page, stub }) => {
        const external: string[] = [];
        page.on('requestfailed', (request) => {
            const { hostname } = new URL(request.url());

            if (hostname !== 'localhost' && hostname !== '127.0.0.1') {
                external.push(request.url());
            }
        });

        await stub.setBacklog(someFlowLogs());
        await gotoFlowLogs(page);
        await expect
            .poll(async () => (await stub.streamRequests()).length)
            .toBeGreaterThan(0);

        expect(external).toEqual([]);
    });
});
