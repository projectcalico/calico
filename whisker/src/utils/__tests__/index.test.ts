import { createEventSource } from '..';
import {
    toFlowLogFilterQuery,
    toDataFilterQuery,
    transformToPolicyMatches,
} from '../filters/flowsFilter';

describe('transformToFilterHintsQuery', () => {
    it('should transform the data', () => {
        const destName = 'dest-1';
        const searchText = 'search';
        expect(
            toDataFilterQuery(
                {
                    dest_name: [destName],
                    dest_namespace: [],
                    source_name: [],
                    source_namespace: [],
                    reporter: [],
                    policy: [],
                },
                'dest_namespace',
                searchText,
            ),
        ).toEqual(
            JSON.stringify({
                dest_names: [{ type: 'Exact', value: destName }],
                dest_namespaces: [{ type: 'Fuzzy', value: searchText }],
            }),
        );
    });

    it('should transform policy filters', () => {
        const policy = {
            name: 'policy-1',
            namespace: 'namespace-1',
            tier: 'tier-1',
            kind: 'kind-1',
        };

        expect(
            toFlowLogFilterQuery({
                dest_name: [],
                dest_namespace: [],
                source_name: [],
                source_namespace: [],
                policy: [policy as any],
                reporter: [],
            }),
        ).toEqual(
            JSON.stringify({
                policies: [
                    {
                        name: { type: 'Exact', value: 'policy-1' },
                        namespace: { type: 'Exact', value: 'namespace-1' },
                        tier: { type: 'Exact', value: 'tier-1' },
                        kind: 'kind-1',
                    },
                ],
            }),
        );
    });

    it('should transform dest name search filter', () => {
        const destName = 'dest-1';
        const searchText = 'search';
        expect(
            toDataFilterQuery(
                {
                    dest_name: [destName],
                    dest_namespace: [],
                    source_name: [],
                    source_namespace: [],
                    policy: [],
                    reporter: [],
                },
                'dest_name',
                searchText,
            ),
        ).toEqual(
            JSON.stringify({
                dest_names: [{ type: 'Fuzzy', value: searchText }],
            }),
        );
    });
});

describe('transformToPolicyMatches', () => {
    it('returns an empty array when given no values', () => {
        expect(transformToPolicyMatches([])).toEqual([]);
    });

    it('only includes fields that are present', () => {
        expect(
            transformToPolicyMatches([{ kind: 'GlobalNetworkPolicy' }]),
        ).toEqual([{ kind: 'GlobalNetworkPolicy' }]);
    });

    it('transforms multiple filters', () => {
        const result = transformToPolicyMatches([
            { tier: 'security', kind: 'NetworkPolicy' },
            { name: 'deny-all', namespace: 'default' },
        ]);

        expect(result).toEqual([
            {
                tier: { type: 'Exact', value: 'security' },
                kind: 'NetworkPolicy',
            },
            {
                name: { type: 'Exact', value: 'deny-all' },
                namespace: { type: 'Exact', value: 'default' },
            },
        ]);
    });
});

Object.defineProperty(window, 'EventSource', {
    writable: true,
    value: jest.fn().mockImplementation((path) => ({
        path,
    })),
});

describe('createEventSource', () => {
    it('should create the event source', () => {
        const path = 'mock-path';
        const eventSource = createEventSource(path);

        expect((eventSource as any).path).toContain(path);
    });
});
