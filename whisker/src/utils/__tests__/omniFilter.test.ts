import { buildStreamPath, transformStartTime } from '@/features/flowLogs/utils';
import { PolicyFilter } from '@/features/flowLogs/components/PolicyOmniFilter';
import {
    buildSearchParamsFromFilters,
    parseFiltersFromParams,
} from '@/hooks/useFlowLogsUrlFilters';
import { FlowsFilter } from '@/types/api';
import { parseStartTime } from '..';
import {
    CustomOmniFilterKeys,
    FilterHintKeys,
    FilterHintTypes,
    FilterKey,
    ListOmniFilterKeys,
    OmniFilterKeys,
    OmniFilterProperties,
    SelectedOmniFilterValues,
    StreamFilterKeys,
    transformToFlowsFilterQuery,
    transformToList,
    transformToPolicyFilterToRequest,
    transformToQueryPage,
    transformToSinlgeValue,
    urlFilterKeys,
} from '../omniFilter';

/**
 * These tests pin the serialization chain that turns a Whisker URL into a
 * request to whisker-backend:
 *
 *   URL search params
 *     -> parseFiltersFromParams   (SelectedOmniFilterValues)
 *     -> transformToFlowsFilterQuery  (the `filters` JSON blob)
 *     -> buildStreamPath          (the flows stream path)
 *
 * Every assertion here is expressed in terms of that public chain rather than
 * the internals of any one transform, so the suite keeps its meaning across
 * refactors of the modules involved. A deep-linked URL producing a different
 * backend query is a user-visible regression (a shared link stops showing the
 * flows it used to), and it is invisible to component-level tests that mock
 * these modules out.
 */

/**
 * Helper: the full URL -> stream path chain, mirroring what FlowLogsPage and
 * useFlowLogsStream do together. `start_time` is stripped from the filter
 * hints the same way FlowLogsPage strips it before handing values to the
 * stream hook.
 */
const urlToStreamPath = (url: string) => {
    const filters = parseFiltersFromParams(new URLSearchParams(url));
    const { start_time: startTimeFilter, ...filterHintValues } = filters;
    const startTime = parseStartTime(startTimeFilter?.[0]);

    return buildStreamPath(
        transformStartTime(startTime),
        transformToFlowsFilterQuery(filterHintValues),
    );
};

/** Helper: parse the `filters` JSON emitted for a set of URL params. */
const urlToFlowsFilter = (url: string): FlowsFilter => {
    const { start_time: _startTime, ...filterHintValues } =
        parseFiltersFromParams(new URLSearchParams(url));
    const query = transformToFlowsFilterQuery(filterHintValues);

    return query === '' ? {} : JSON.parse(query);
};

describe('URL <-> filter state round trip', () => {
    // Filter states expressed the way they live in the URL: every value is a
    // list of strings. `policy` is the one key that carries JSON.
    const corpus: Array<{
        name: string;
        filters: Record<string, string[]>;
    }> = [
        {
            name: 'a single value',
            filters: { source_name: ['nginx'] },
        },
        {
            name: 'multiple values for one key',
            filters: { dest_namespace: ['default', 'kube-system'] },
        },
        {
            name: 'several keys at once',
            filters: {
                source_namespace: ['prod'],
                dest_port: ['443'],
                protocol: ['tcp'],
                action: ['deny'],
            },
        },
        {
            name: 'every filter key populated',
            filters: {
                source_name: ['nginx'],
                source_namespace: ['prod'],
                dest_name: ['api'],
                dest_namespace: ['default'],
                dest_port: ['8080'],
                protocol: ['udp'],
                action: ['allow'],
                staged_action: ['Deny'],
                reporter: ['Src'],
                start_time: ['15'],
            },
        },
        {
            name: 'values that need URL encoding',
            filters: {
                source_name: [
                    'has space',
                    'has&ampersand',
                    'has=equals',
                    'has?question',
                    'has#hash',
                    'has%percent',
                    'has+plus',
                    'has/slash',
                    '100%',
                ],
            },
        },
        {
            name: 'unicode values',
            filters: { dest_name: ['ünïcödé-workload', '日本語'] },
        },
        {
            name: 'an empty-string value',
            filters: { source_name: [''] },
        },
        {
            name: 'duplicate values for one key',
            filters: { source_namespace: ['default', 'default'] },
        },
    ];

    it.each(corpus)(
        'should survive a URL round trip with $name',
        ({ filters }) => {
            const params = buildSearchParamsFromFilters(
                new URLSearchParams(),
                filters,
            );

            // Serialize and reparse, exactly as a browser navigation would.
            const reparsed = parseFiltersFromParams(
                new URLSearchParams(params.toString()),
            );

            expect(reparsed).toEqual(filters);
        },
    );

    it('should round trip policy filters through their JSON encoding', () => {
        // This is the shape PolicyOmniFilter puts on the URL.
        const policies: PolicyFilter[] = [
            {
                kind: 'CalicoNetworkPolicy',
                tier: 'default',
                namespace: 'prod',
                name: 'allow-nginx',
            },
            { kind: 'Profile' },
        ];

        const params = buildSearchParamsFromFilters(new URLSearchParams(), {
            policy: [JSON.stringify(policies)],
        });

        const reparsed = parseFiltersFromParams(
            new URLSearchParams(params.toString()),
        );

        expect(reparsed.policy).toEqual(policies);
    });

    it('should round trip the no-policy selection', () => {
        // PolicyOmniFilter writes this exact literal for "no policy".
        const params = buildSearchParamsFromFilters(new URLSearchParams(), {
            policy: ['[{"kind": "Profile"}]'],
        });

        expect(
            parseFiltersFromParams(new URLSearchParams(params.toString()))
                .policy,
        ).toEqual([{ kind: 'Profile' }]);
    });

    it('should drop a policy filter that is not valid JSON rather than throw', () => {
        const params = new URLSearchParams('policy=not-json');

        expect(parseFiltersFromParams(params).policy).toEqual([]);
    });

    it('should preserve unrelated search params across a round trip', () => {
        const params = buildSearchParamsFromFilters(
            new URLSearchParams('ref=docs&utm_source=email'),
            { source_name: ['nginx'] },
        );

        expect(params.get('ref')).toBe('docs');
        expect(params.get('utm_source')).toBe('email');
    });
});

describe('URL -> flows filter query', () => {
    // One row per filter key, pinning the wire shape whisker-backend receives.
    const cases: Array<{
        name: string;
        url: string;
        expected: FlowsFilter;
    }> = [
        {
            name: 'no filters',
            url: '',
            expected: {},
        },
        {
            name: 'source_namespace becomes an exact source_namespaces match',
            url: 'source_namespace=default',
            expected: {
                source_namespaces: [{ type: 'Exact', value: 'default' }],
            },
        },
        {
            name: 'multiple values become multiple exact matches',
            url: 'source_namespace=default&source_namespace=kube-system',
            expected: {
                source_namespaces: [
                    { type: 'Exact', value: 'default' },
                    { type: 'Exact', value: 'kube-system' },
                ],
            },
        },
        {
            name: 'source_name becomes source_names',
            url: 'source_name=nginx',
            expected: { source_names: [{ type: 'Exact', value: 'nginx' }] },
        },
        {
            name: 'dest_namespace becomes dest_namespaces',
            url: 'dest_namespace=prod',
            expected: {
                dest_namespaces: [{ type: 'Exact', value: 'prod' }],
            },
        },
        {
            name: 'dest_name becomes dest_names',
            url: 'dest_name=api',
            expected: { dest_names: [{ type: 'Exact', value: 'api' }] },
        },
        {
            name: 'protocol becomes protocols',
            url: 'protocol=tcp',
            expected: { protocols: [{ type: 'Exact', value: 'tcp' }] },
        },
        {
            name: 'dest_port is coerced to a number',
            url: 'dest_port=8080',
            expected: { dest_ports: [{ type: 'Exact', value: 8080 }] },
        },
        {
            name: 'reporter is sent as a bare string, not a match object',
            url: 'reporter=Src',
            expected: { reporter: 'Src' as unknown as FlowsFilter['reporter'] },
        },
        {
            name: 'action is sent as a bare string list',
            url: 'action=deny',
            expected: {
                actions: ['deny'] as unknown as FlowsFilter['actions'],
            },
        },
        {
            name: 'staged_action maps onto pending_actions',
            url: 'staged_action=Deny',
            expected: {
                pending_actions: [
                    'Deny',
                ] as unknown as FlowsFilter['pending_actions'],
            },
        },
        {
            name: 'a policy filter becomes an exact-match policy object',
            url: `policy=${encodeURIComponent(
                JSON.stringify([
                    {
                        kind: 'CalicoNetworkPolicy',
                        tier: 'default',
                        namespace: 'prod',
                        name: 'allow-nginx',
                    },
                ]),
            )}`,
            expected: {
                policies: [
                    {
                        name: { type: 'Exact', value: 'allow-nginx' },
                        namespace: { type: 'Exact', value: 'prod' },
                        tier: { type: 'Exact', value: 'default' },
                        kind: 'CalicoNetworkPolicy',
                    },
                ] as unknown as FlowsFilter['policies'],
            },
        },
        {
            name: 'several filters combine into one query',
            url: 'source_namespace=default&dest_port=443&protocol=tcp&action=deny&reporter=Dst',
            expected: {
                source_namespaces: [{ type: 'Exact', value: 'default' }],
                dest_ports: [{ type: 'Exact', value: 443 }],
                protocols: [{ type: 'Exact', value: 'tcp' }],
                actions: ['deny'] as unknown as FlowsFilter['actions'],
                reporter: 'Dst' as unknown as FlowsFilter['reporter'],
            },
        },
        {
            name: 'unknown search params are ignored',
            url: 'source_name=nginx&utm_source=email',
            expected: { source_names: [{ type: 'Exact', value: 'nginx' }] },
        },
    ];

    it.each(cases)('should map $name', ({ url, expected }) => {
        expect(urlToFlowsFilter(url)).toEqual(expected);
    });

    it('should send only the first value for single-value filters', () => {
        // `action` and `reporter` take the head of the list; a URL carrying
        // two of them must not widen the query.
        expect(urlToFlowsFilter('action=deny&action=allow')).toEqual({
            actions: ['deny'],
        });
        expect(urlToFlowsFilter('reporter=Src&reporter=Dst')).toEqual({
            reporter: 'Src',
        });
    });

    it('should omit a filter whose value list is empty', () => {
        expect(
            transformToFlowsFilterQuery({
                source_name: [],
                dest_name: undefined,
            }),
        ).toBe('');
    });

    it('should contribute no filter hints for start_time', () => {
        // start_time reaches the backend as startTimeGte, not as a filter
        // hint. FlowLogsPage strips it before building the query, but if it
        // slips through, the query must not gain a start_time constraint:
        // keys without a wire key are skipped, leaving an empty query.
        expect(transformToFlowsFilterQuery({ start_time: ['15'] })).toBe('');
    });

    it('should return an empty string when nothing is filtered', () => {
        expect(transformToFlowsFilterQuery({})).toBe('');
    });

    it('should ignore a URL carrying the unsupported pending_action param', () => {
        // pending_action used to be accepted off the URL without an
        // OmniFilterProperties entry, which crashed the query builder and
        // blanked the page. URL keys are now derived from the registry, so
        // an unsupported param is ignored like any other unknown param.
        expect(urlToFlowsFilter('pending_action=Allow')).toEqual({});
    });

    describe('dest_port coercion', () => {
        // dest_port is the only filter that changes type on the wire, and the
        // coercion silently drops values. Pinned so a refactor has to decide
        // deliberately rather than by accident.
        it.each([
            ['8080', [{ type: 'Exact', value: 8080 }]],
            ['65535', [{ type: 'Exact', value: 65535 }]],
            // Number('') is 0, which is falsy and therefore dropped.
            ['', undefined],
            // 0 is falsy and dropped, so port 0 cannot be filtered on.
            ['0', undefined],
            // Non-numeric input becomes NaN, which is falsy and dropped.
            ['not-a-port', undefined],
        ])('should map dest_port=%s to %p', (port, expected) => {
            const result = urlToFlowsFilter(`dest_port=${port}`);

            expect(result.dest_ports).toEqual(expected);
        });
    });

    describe('filter hint requests', () => {
        it('should exclude the list being populated and search it fuzzily', () => {
            // When the user types in the Source Namespace filter, the query
            // sent to fetch its options must not constrain itself by the
            // source namespaces already selected.
            const values: SelectedOmniFilterValues = {
                source_namespace: ['default'],
                dest_name: ['api'],
            };

            const query = JSON.parse(
                transformToFlowsFilterQuery(values, 'source_namespace', 'kube'),
            );

            expect(query).toEqual({
                dest_names: [{ type: 'Exact', value: 'api' }],
                source_namespaces: [{ type: 'Fuzzy', value: 'kube' }],
            });
        });

        it('should exclude the list being populated when there is no search term', () => {
            const values: SelectedOmniFilterValues = {
                source_namespace: ['default'],
                dest_name: ['api'],
            };

            expect(
                JSON.parse(
                    transformToFlowsFilterQuery(values, 'source_namespace'),
                ),
            ).toEqual({ dest_names: [{ type: 'Exact', value: 'api' }] });
        });

        it('should route policy sub-filter searches under the parent policies key', () => {
            // policyName/policyNamespace/policyTier/policyKind all nest their
            // search under `policies` via parentFilterKey.
            const searchesByFilter = {
                policyName: { name: { type: 'Fuzzy', value: 'allow' } },
                policyNamespace: {
                    namespace: { type: 'Fuzzy', value: 'allow' },
                },
                policyTier: { tier: { type: 'Fuzzy', value: 'allow' } },
                policyKind: { kind: 'allow' },
            };

            for (const [filterId, expected] of Object.entries(
                searchesByFilter,
            )) {
                const query = JSON.parse(
                    transformToFlowsFilterQuery(
                        {},
                        filterId as Parameters<
                            typeof transformToFlowsFilterQuery
                        >[1],
                        'allow',
                    ),
                );

                expect(query).toEqual({ policies: [expected] });
            }
        });
    });
});

describe('URL -> flows stream path', () => {
    it('should default to a one minute lookback when start_time is absent', () => {
        expect(urlToStreamPath('')).toBe('flows?watch=true&startTimeGte=-60');
    });

    it.each([
        ['1', -60],
        ['15', -900],
        ['60', -3600],
        // Above the 60 minute maximum, parseStartTime falls back to 1 minute.
        ['61', -60],
        // Non-numeric input falls back to 1 minute.
        ['garbage', -60],
    ])(
        'should turn start_time=%s into startTimeGte=%s',
        (startTime, expected) => {
            expect(urlToStreamPath(`start_time=${startTime}`)).toBe(
                `flows?watch=true&startTimeGte=${expected}`,
            );
        },
    );

    it('should not send start_time as a backend filter', () => {
        // start_time is expressed only via startTimeGte; leaking it into the
        // filters blob would make the backend reject or ignore the query.
        expect(urlToStreamPath('start_time=15')).not.toContain('filters');
    });

    it('should carry the filters blob unencoded in the query string', () => {
        // EventSource encodes the URL itself, so objToQueryStr must not
        // pre-encode. Double-encoding here is a silent no-results bug.
        expect(urlToStreamPath('source_namespace=default')).toBe(
            'flows?watch=true&filters={"source_namespaces":[{"type":"Exact","value":"default"}]}&startTimeGte=-60',
        );
    });

    it('should combine filters and a start time', () => {
        expect(urlToStreamPath('action=deny&start_time=15')).toBe(
            'flows?watch=true&filters={"actions":["deny"]}&startTimeGte=-900',
        );
    });
});

describe('filter key metadata', () => {
    // Structural invariants over OmniFilterProperties. A refactor that adds a
    // filter key or renames a wire key trips these instead of silently
    // shipping a filter that never reaches the backend.
    const allKeys = Object.values(OmniFilterKeys);

    it('should describe every omni filter key', () => {
        expect(allKeys.sort()).toEqual(
            Object.keys(OmniFilterProperties).sort(),
        );
    });

    it.each(allKeys)('should give %s a label', (key) => {
        expect(OmniFilterProperties[key].label).toBeTruthy();
    });

    it.each(
        allKeys.filter(
            (key) =>
                // start_time is applied as startTimeGte, not as a filter hint.
                key !== FilterKey.start_time,
        ),
    )('should give %s a filter hints key', (key) => {
        expect(OmniFilterProperties[key].filterHintsKey).toBeTruthy();
    });

    it('should map every filter hint key to a hint type', () => {
        expect(Object.keys(FilterHintTypes).sort()).toEqual(
            Object.keys(FilterHintKeys).sort(),
        );
    });

    it('should give every list filter a page size', () => {
        for (const key of Object.values(ListOmniFilterKeys)) {
            if (key === FilterKey.reporter) {
                // reporter is a fixed radio list, not a paged data list.
                continue;
            }

            expect(OmniFilterProperties[key].limit).toBeGreaterThan(0);
        }
    });

    it('should not reuse a filter hints key for two different filters', () => {
        const hintKeys = allKeys
            .filter((key) => key !== FilterKey.start_time)
            .map((key) => OmniFilterProperties[key].filterHintsKey);

        expect(new Set(hintKeys).size).toBe(hintKeys.length);
    });

    it('should accept exactly the supported URL filter keys', () => {
        // The URL surface is derived from the registry, so a registry edit
        // that adds, drops, or renames a URL param trips this pin. Deep links
        // in the wild depend on these exact names.
        expect([...urlFilterKeys].sort()).toEqual([
            'action',
            'dest_name',
            'dest_namespace',
            'dest_port',
            'policy',
            'protocol',
            'reporter',
            'source_name',
            'source_namespace',
            'staged_action',
            'start_time',
        ]);
    });

    it('should not accept the unsupported pending_action key off the URL', () => {
        // pending_action once slipped into the URL key list without a
        // registry entry and crashed the page; it must stay unaccepted
        // (staged_action is the filter that maps onto pending_actions).
        expect(
            parseFiltersFromParams(
                new URLSearchParams('pending_action=Allow'),
            ),
        ).toEqual({});
    });

    it('should classify start_time as a stream filter and a custom filter', () => {
        // start_time restarts the stream (startTimeGte) rather than being a
        // filter hint, and it renders as a custom omni filter component.
        expect(Object.values(StreamFilterKeys)).toEqual([FilterKey.start_time]);
        expect(CustomOmniFilterKeys.start_time).toBe(FilterKey.start_time);
    });

    it('should point every policy sub-filter at the policies parent key', () => {
        for (const key of [
            FilterKey.policyName,
            FilterKey.policyNamespace,
            FilterKey.policyTier,
            FilterKey.policyKind,
        ]) {
            expect(OmniFilterProperties[key].parentFilterKey).toBe('policies');
        }
    });
});

describe('reporter filter component props', () => {
    // The reporter omni filter is a fixed radio list rather than a paged data
    // list, so its behaviour lives in filterComponentProps.
    const componentProps =
        OmniFilterProperties[FilterKey.reporter].filterComponentProps!;

    it('should offer exactly the Source and Destination options', () => {
        expect(componentProps.filters).toEqual([
            { label: 'Source', value: 'Src' },
            { label: 'Destination', value: 'Dst' },
        ]);
        expect(componentProps.listType).toBe('radio');
        expect(componentProps.showSearch).toBe(false);
    });

    it('should not request data on ready since the option list is fixed', () => {
        expect(componentProps.onReady!()).toBeUndefined();
    });

    it.each([
        ['Src', 'Source'],
        ['Dst', 'Destination'],
    ])(
        'should render the selected value %s as the label %s',
        (value, label) => {
            expect(
                componentProps.formatSelectedLabel!([{ label, value }]),
            ).toBe(label);
        },
    );

    it('should render an empty selection as an empty label', () => {
        expect(componentProps.formatSelectedLabel!([])).toBe('');
    });
});

describe('transformToListFilter', () => {
    it('should treat an undefined filter list as no filters', () => {
        // List filters share this transform; an absent value must behave the
        // same as an empty selection and produce no query fragment.
        expect(
            OmniFilterProperties[FilterKey.protocol]
                .transformToFilterHintRequest!(
                undefined as unknown as string[],
            ),
        ).toBeUndefined();
    });
});

describe('transformToPolicyFilterToRequest', () => {
    it('should omit fields the user left blank', () => {
        expect(
            transformToPolicyFilterToRequest([{ name: 'allow-nginx' }]),
        ).toEqual([{ name: { type: 'Exact', value: 'allow-nginx' } }]);
    });

    it('should send kind verbatim rather than as a match object', () => {
        expect(transformToPolicyFilterToRequest([{ kind: 'Profile' }])).toEqual(
            [{ kind: 'Profile' }],
        );
    });

    it('should transform each policy query independently', () => {
        expect(
            transformToPolicyFilterToRequest([
                { name: 'first' },
                { namespace: 'second' },
            ]),
        ).toEqual([
            { name: { type: 'Exact', value: 'first' } },
            { namespace: { type: 'Exact', value: 'second' } },
        ]);
    });

    it('should produce an empty query for an empty policy filter', () => {
        expect(transformToPolicyFilterToRequest([{}])).toEqual([{}]);
    });
});

describe('transformToList', () => {
    it('should keep only the first value', () => {
        expect(transformToList(['deny', 'allow'])).toEqual(['deny']);
    });
});

describe('transformToSinlgeValue', () => {
    it('should unwrap the first value', () => {
        expect(transformToSinlgeValue(['Src', 'Dst'])).toBe('Src');
    });
});

describe('transformToQueryPage', () => {
    it('should map filter hints to select options and advance the page', () => {
        expect(
            transformToQueryPage(
                {
                    items: [{ value: 'default' }, { value: 'kube-system' }],
                    total: { totalResults: 42, totalPages: 3 },
                },
                1,
            ),
        ).toEqual({
            items: [
                { label: 'default', value: 'default' },
                { label: 'kube-system', value: 'kube-system' },
            ],
            total: 42,
            currentPage: 1,
            nextPage: 2,
        });
    });
});
