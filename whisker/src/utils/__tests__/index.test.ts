import { createEventSource } from '..';
import { ListOmniFilterKeys, transformToFlowsFilterQuery } from '../omniFilter';

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
                    policy: [],
                    policyV2: [],
                    policyV2Namespace: [],
                    policyV2Tier: [],
                    policyV2Kind: [],
                    reporter: [],
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

    it('should policy filters', () => {
        const policy = 'policy-1';
        expect(
            transformToFlowsFilterQuery({
                dest_name: [],
                dest_namespace: [],
                source_name: [],
                source_namespace: [],
                policy: [policy],
                policyV2: [],
                policyV2Namespace: [],
                policyV2Tier: [],
                policyV2Kind: [],
                reporter: [],
            }),
        ).toEqual(
            JSON.stringify({
                policies: [{ name: { type: 'Exact', value: policy } }],
            }),
        );
    });

    it('should policy search filter', () => {
        const policy = 'policy-1';
        const searchText = 'search';
        expect(
            transformToFlowsFilterQuery(
                {
                    dest_name: [],
                    dest_namespace: [],
                    source_name: [],
                    source_namespace: [],
                    policy: [policy],
                    policyV2: [],
                    policyV2Namespace: [],
                    policyV2Tier: [],
                    policyV2Kind: [],
                    reporter: [],
                },
                ListOmniFilterKeys.policy,
                searchText,
            ),
        ).toEqual(
            JSON.stringify({
                policies: [{ name: { type: 'Fuzzy', value: searchText } }],
            }),
        );
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
