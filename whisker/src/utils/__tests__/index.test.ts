import { OmniFilterParam, transformToFlowsFilterQuery } from '../omniFilter';

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
                },
                OmniFilterParam.dest_namespace,
                searchText,
            ),
        ).toEqual(
            JSON.stringify({
                dest_names: [{ type: 'exact', value: destName }],
                source_names: [],
                source_namespaces: [],
                dest_namespaces: [{ type: 'fuzzy', value: searchText }],
                actions: [],
                protocols: [],
                dest_ports: [],
            }),
        );
    });
});
