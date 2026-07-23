import { PolicyFilter } from '../..';
import { PolicyQuery, QuerySelect } from '../../QueryList';
import {
    getDefaultExpanded,
    isQueryEmpty,
    transformToFilterOptions,
    transformToQueries,
    updateQueryField,
} from '..';

describe('transformToQueries', () => {
    it('should return [{}] when given an empty array', () => {
        expect(transformToQueries([])).toEqual([{}]);
    });

    it('should transform a single filter with all fields', () => {
        const filters: PolicyFilter[] = [
            {
                kind: 'NetworkPolicy',
                tier: 'default',
                namespace: 'kube-system',
                name: 'allow-dns',
            },
        ];

        expect(transformToQueries(filters)).toEqual([
            {
                kind: { label: 'NetworkPolicy', value: 'NetworkPolicy' },
                tier: { label: 'default', value: 'default' },
                namespace: { label: 'kube-system', value: 'kube-system' },
                name: { label: 'allow-dns', value: 'allow-dns' },
            },
        ]);
    });

    it('should only include truthy fields', () => {
        const filters: PolicyFilter[] = [{ kind: 'NetworkPolicy', name: '' }];

        expect(transformToQueries(filters)).toEqual([
            {
                kind: { label: 'NetworkPolicy', value: 'NetworkPolicy' },
            },
        ]);
    });

    it('should transform multiple filters', () => {
        const filters: PolicyFilter[] = [
            { kind: 'NetworkPolicy' },
            { tier: 'default', name: 'deny-all' },
        ];

        expect(transformToQueries(filters)).toEqual([
            { kind: { label: 'NetworkPolicy', value: 'NetworkPolicy' } },
            {
                tier: { label: 'default', value: 'default' },
                name: { label: 'deny-all', value: 'deny-all' },
            },
        ]);
    });
});

describe('transformToFilterOptions', () => {
    it('should return an empty array when all queries are empty', () => {
        expect(transformToFilterOptions([{}])).toEqual([]);
    });

    it('should extract values from query select options', () => {
        const queries: PolicyQuery[] = [
            {
                kind: { label: 'NetworkPolicy', value: 'NetworkPolicy' },
                tier: { label: 'default', value: 'default' },
            },
        ];

        expect(transformToFilterOptions(queries)).toEqual([
            { kind: 'NetworkPolicy', tier: 'default' },
        ]);
    });

    it('should handle null values by mapping them to undefined', () => {
        const queries: PolicyQuery[] = [
            {
                kind: { label: 'NetworkPolicy', value: 'NetworkPolicy' },
                tier: null,
            },
        ];

        const result = transformToFilterOptions(queries);

        expect(result).toEqual([{ kind: 'NetworkPolicy', tier: undefined }]);
    });

    it('should filter out completely empty query results', () => {
        const queries: PolicyQuery[] = [
            {
                kind: { label: 'NetworkPolicy', value: 'NetworkPolicy' },
            },
            {},
        ];

        expect(transformToFilterOptions(queries)).toEqual([
            { kind: 'NetworkPolicy' },
        ]);
    });

    it('should transform multiple queries', () => {
        const queries: PolicyQuery[] = [
            {
                kind: { label: 'NetworkPolicy', value: 'NetworkPolicy' },
                name: { label: 'allow-dns', value: 'allow-dns' },
            },
            {
                tier: { label: 'default', value: 'default' },
            },
        ];

        expect(transformToFilterOptions(queries)).toEqual([
            { kind: 'NetworkPolicy', name: 'allow-dns' },
            { tier: 'default' },
        ]);
    });
});

describe('isQueryEmpty', () => {
    it('returns true for an empty object', () => {
        expect(isQueryEmpty({})).toBe(true);
    });

    it('returns true when all values are null', () => {
        expect(isQueryEmpty({ kind: null, tier: null })).toBe(true);
    });

    it('returns true when all values are undefined', () => {
        expect(isQueryEmpty({ kind: undefined, tier: undefined })).toBe(true);
    });

    it('returns false when at least one value is set', () => {
        expect(
            isQueryEmpty({
                kind: { label: 'NetworkPolicy', value: 'NetworkPolicy' },
            }),
        ).toBe(false);
    });

    it('returns false when some values are set and some are null', () => {
        expect(
            isQueryEmpty({
                kind: { label: 'NetworkPolicy', value: 'NetworkPolicy' },
                tier: null,
            }),
        ).toBe(false);
    });
});

describe('updateQueryField', () => {
    const kindOption = { label: 'NetworkPolicy', value: 'NetworkPolicy' };
    const tierOption = { label: 'default', value: 'default' };
    const nsOption = { label: 'kube-system', value: 'kube-system' };

    it('sets a field on the target query', () => {
        const queries: QuerySelect[] = [{}];

        expect(updateQueryField(queries, 0, 'kind', kindOption)).toEqual([
            { kind: kindOption },
        ]);
    });

    it('overwrites an existing field value', () => {
        const queries: QuerySelect[] = [{ kind: kindOption }];
        const newKind = {
            label: 'GlobalNetworkPolicy',
            value: 'GlobalNetworkPolicy',
        };

        expect(updateQueryField(queries, 0, 'kind', newKind)).toEqual([
            { kind: newKind },
        ]);
    });

    it('removes the field when value is null', () => {
        const queries: QuerySelect[] = [{ kind: kindOption, tier: tierOption }];

        expect(updateQueryField(queries, 0, 'kind', null)).toEqual([
            { tier: tierOption },
        ]);
    });

    it('does not modify queries at other indices', () => {
        const queries: QuerySelect[] = [
            { kind: kindOption },
            { tier: tierOption },
        ];

        const result = updateQueryField(queries, 1, 'namespace', nsOption);

        expect(result[0]).toEqual({ kind: kindOption });
        expect(result[1]).toEqual({ tier: tierOption, namespace: nsOption });
    });

    it('returns a new array without mutating the original', () => {
        const queries: QuerySelect[] = [{ kind: kindOption }];
        const result = updateQueryField(queries, 0, 'tier', tierOption);

        expect(result).not.toBe(queries);
        expect(queries[0]).toEqual({ kind: kindOption });
    });
});

describe('getDefaultExpanded', () => {
    it('returns empty string for an empty array', () => {
        expect(getDefaultExpanded([])).toBe('');
    });

    it('returns the index of the last query when it is empty', () => {
        const queries: QuerySelect[] = [
            { kind: { label: 'NetworkPolicy', value: 'NetworkPolicy' } },
            {},
        ];

        expect(getDefaultExpanded(queries)).toBe('1');
    });

    it('returns empty string when the last query has values', () => {
        const queries: QuerySelect[] = [
            { kind: { label: 'NetworkPolicy', value: 'NetworkPolicy' } },
        ];

        expect(getDefaultExpanded(queries)).toBe('');
    });

    it('returns "0" when the only query is empty', () => {
        expect(getDefaultExpanded([{}])).toBe('0');
    });

    it('returns empty string when the last query has at least one non-null value', () => {
        const queries: QuerySelect[] = [
            {},
            { kind: null, tier: { label: 'default', value: 'default' } },
        ];

        expect(getDefaultExpanded(queries)).toBe('');
    });
});
