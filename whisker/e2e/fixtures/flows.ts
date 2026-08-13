/**
 * Flow log fixtures, shaped like the `FlowLog` payload whisker-backend streams
 * (see src/types/api.ts). They live here rather than in the stub server so the
 * stub stays a dumb programmable pipe and each test states its own data.
 */

export type StubPolicy = {
    kind: string;
    name: string;
    namespace: string;
    tier: string;
    action: string;
    policy_index: number | null;
    rule_index: number | null;
    trigger?: StubPolicy | null;
};

export type StubFlowLog = {
    start_time: string;
    end_time: string;
    action: string;
    source_name: string;
    source_namespace: string;
    source_labels: string;
    dest_name: string;
    dest_namespace: string;
    dest_labels: string;
    protocol: string;
    dest_port: string;
    reporter: string;
    packets_in: string;
    packets_out: string;
    bytes_in: string;
    bytes_out: string;
    policies: Record<string, StubPolicy[]>;
};

export const aPolicy = (overrides: Partial<StubPolicy> = {}): StubPolicy => ({
    kind: 'CalicoNetworkPolicy',
    name: 'default-allow',
    namespace: 'default',
    tier: 'default',
    action: 'Allow',
    policy_index: 0,
    rule_index: 0,
    trigger: null,
    ...overrides,
});

/**
 * Times default to "just now" so the flows fall inside the app's default one
 * minute lookback and inside the one hour clamp in getTimeInSeconds. Override
 * them when a test needs an exact rendered timestamp.
 */
export const aFlowLog = (overrides: Partial<StubFlowLog> = {}): StubFlowLog => {
    const now = new Date();

    return {
        start_time: now.toISOString(),
        end_time: now.toISOString(),
        action: 'Allow',
        source_name: 'source-workload',
        source_namespace: 'default',
        source_labels: 'app=source',
        dest_name: 'dest-workload',
        dest_namespace: 'default',
        dest_labels: 'app=dest',
        protocol: 'tcp',
        dest_port: '8080',
        reporter: 'Src',
        packets_in: '10',
        packets_out: '20',
        bytes_in: '100',
        bytes_out: '200',
        // whisker-backend always emits both keys (they have no omitempty), so
        // fixtures do too. See the pending-null regression spec for what
        // happens when one of them arrives as null.
        policies: { enforced: [aPolicy()], pending: [aPolicy()] },
        ...overrides,
    };
};

/** The source name `manyFlowLogs` gives the flow at `index`. */
export const flowName = (index: number, prefix = 'flow') =>
    `${prefix}-${String(index).padStart(4, '0')}`;

const FLOW_SPACING_MS = 100;

/**
 * `count` distinct flows, oldest first, a tenth of a second apart and ending
 * "now". Names are zero padded so no name is a substring of another and a
 * locator for `flow-0001` cannot also match `flow-0010`.
 *
 * Timestamps are strictly increasing so the table's default start_time
 * descending sort has an unambiguous order to put them in: index 0 renders last
 * and index count-1 renders first. Generate one array and emit slices of it
 * when a test streams several batches, so ordering holds across batches too.
 *
 * Keep counts under ~600: beyond that the batch stretches past the app's
 * default one minute lookback.
 */
export const manyFlowLogs = (
    count: number,
    {
        prefix = 'flow',
        ...overrides
    }: Partial<StubFlowLog> & { prefix?: string } = {},
): StubFlowLog[] => {
    const oldest = Date.now() - count * FLOW_SPACING_MS;

    return Array.from({ length: count }, (_, index) => {
        const time = new Date(oldest + index * FLOW_SPACING_MS).toISOString();

        return aFlowLog({
            source_name: flowName(index, prefix),
            start_time: time,
            end_time: time,
            ...overrides,
        });
    });
};

/**
 * Flows with fixed timestamps, for screenshot baselines.
 *
 * Everything else in this file is stamped "now", which renders a different
 * `toLocaleTimeString()` on every run and would make every visual baseline
 * fail. These are pinned to a fixed instant instead; combined with the
 * `locale`/`timezoneId` set in playwright.config.ts, the rendered times are
 * byte-identical run to run.
 *
 * The times are also in the past, which keeps `useShouldAnimate` from playing
 * the row entry animation: it only animates rows newer than the highest
 * start_time seen so far, and on first paint that baseline is 0.
 */
const STATIC_START_MS = Date.UTC(2026, 0, 15, 9, 30, 0);
const STATIC_SPACING_MS = 1_000;

export const staticFlowLogs = (): StubFlowLog[] =>
    [
        {
            source_name: 'nginx-frontend',
            source_namespace: 'web',
            dest_name: 'orders-api',
            dest_namespace: 'backend',
            action: 'Allow',
            protocol: 'tcp',
            dest_port: '8080',
            reporter: 'Src',
        },
        {
            source_name: 'batch-runner',
            source_namespace: 'jobs',
            dest_name: 'postgres',
            dest_namespace: 'data',
            action: 'Deny',
            protocol: 'tcp',
            dest_port: '5432',
            reporter: 'Dst',
        },
        {
            source_name: 'metrics-agent',
            source_namespace: 'observability',
            dest_name: 'prometheus',
            dest_namespace: 'observability',
            action: 'Allow',
            protocol: 'udp',
            dest_port: '9090',
            reporter: 'Src',
        },
        {
            source_name: 'checkout-api',
            source_namespace: 'shop',
            dest_name: 'payments',
            dest_namespace: 'billing',
            action: 'Allow',
            protocol: 'tcp',
            dest_port: '8443',
            reporter: 'Src',
        },
        {
            source_name: 'audit-sidecar',
            source_namespace: 'shop',
            dest_name: 'log-collector',
            dest_namespace: 'observability',
            action: 'Deny',
            protocol: 'tcp',
            dest_port: '24224',
            reporter: 'Dst',
        },
    ].map((flow, index) => {
        const time = new Date(
            STATIC_START_MS + index * STATIC_SPACING_MS,
        ).toISOString();

        return aFlowLog({
            ...flow,
            start_time: time,
            end_time: time,
            packets_in: '1024',
            packets_out: '2048',
            bytes_in: '4096',
            bytes_out: '8192',
            // Both traces populated, and a trigger, so the details view renders
            // its full policy surface rather than the empty-table case.
            policies: {
                enforced: [
                    aPolicy({
                        name: 'allow-frontend',
                        namespace: flow.source_namespace,
                        trigger: aPolicy({ name: 'staged-deny-all' }),
                    }),
                ],
                pending: [aPolicy({ name: 'default-deny', action: 'Deny' })],
            },
        });
    });

/** A small, all-distinct set of flows for assertions on rendered rows. */
export const someFlowLogs = (): StubFlowLog[] => [
    aFlowLog({
        source_name: 'nginx-frontend',
        source_namespace: 'web',
        dest_name: 'orders-api',
        dest_namespace: 'backend',
        action: 'Allow',
        protocol: 'tcp',
        dest_port: '8080',
        reporter: 'Src',
    }),
    aFlowLog({
        source_name: 'batch-runner',
        source_namespace: 'jobs',
        dest_name: 'postgres',
        dest_namespace: 'data',
        action: 'Deny',
        protocol: 'tcp',
        dest_port: '5432',
        reporter: 'Dst',
    }),
    aFlowLog({
        source_name: 'metrics-agent',
        source_namespace: 'observability',
        dest_name: 'prometheus',
        dest_namespace: 'observability',
        action: 'Allow',
        protocol: 'udp',
        dest_port: '9090',
        reporter: 'Src',
    }),
];
