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
                    reporter: [],
                    policy: [],
                    policyNamespace: [],
                    policyTier: [],
                    policyKind: [],
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
        const policy = 'policy-1';
        expect(
            transformToFlowsFilterQuery({
                dest_name: [],
                dest_namespace: [],
                source_name: [],
                source_namespace: [],
                policy: [policy],
                policyNamespace: [],
                policyTier: [],
                policyKind: [],
                reporter: [],
            }),
        ).toEqual(
            JSON.stringify({
                policies: [{ type: 'Exact', value: policy }],
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
