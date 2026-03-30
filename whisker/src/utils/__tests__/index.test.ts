import { createEventSource } from '..';
import {
    ListOmniFilterKeys,
    transformToFlowsFilterQuery,
    transformToPolicyFilterToRequest,
} from '../omniFilter';

describe('transformToFilterHintsQuery', () => {
    it('should transform the data', () => {
        const destName = 'dest-1';
        const searchText = 'search';
        expect(
            transformToFlowsFilterQuery(
                {
                    dest_name: [destName],
                    dest_namespace: [],
                    source_name: [],
                    source_namespace: [],
                    reporter: [],
                    policy: [],
                    policyNamespace: [],
                    policyTier: [],
                    policyKind: [],
                    policyName: [],
                },
                ListOmniFilterKeys.dest_namespace,
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
            transformToFlowsFilterQuery({
                dest_name: [],
                dest_namespace: [],
                source_name: [],
                source_namespace: [],
                policy: [policy as any],
                policyNamespace: [],
                policyTier: [],
                policyKind: [],
                reporter: [],
                policyName: [],
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
            transformToFlowsFilterQuery(
                {
                    dest_name: [destName],
                    dest_namespace: [],
                    source_name: [],
                    source_namespace: [],
                    policy: [],
                    policyNamespace: [],
                    policyTier: [],
                    policyKind: [],
                    reporter: [],
                    policyName: [],
                },
                ListOmniFilterKeys.dest_name,
                searchText,
            ),
        ).toEqual(
            JSON.stringify({
                dest_names: [{ type: 'Fuzzy', value: searchText }],
            }),
        );
    });
});

describe('transformToPolicyFilterToRequest', () => {
    it('returns an empty array when given no values', () => {
        expect(transformToPolicyFilterToRequest([])).toEqual([]);
    });

    it('only includes fields that are present', () => {
        expect(
            transformToPolicyFilterToRequest([{ kind: 'GlobalNetworkPolicy' }]),
        ).toEqual([{ kind: 'GlobalNetworkPolicy' }]);
    });

    it('transforms multiple filters', () => {
        const result = transformToPolicyFilterToRequest([
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
