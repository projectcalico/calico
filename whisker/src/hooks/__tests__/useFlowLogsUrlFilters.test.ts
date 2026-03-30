import {
    transformJSON,
    parseFiltersFromParams,
    buildSearchParamsFromFilters,
    useFlowLogsUrlFilters,
} from '../useFlowLogsUrlFilters';
import { renderHookWithRouter, act } from '@/test-utils/helper';

describe('useFlowLogsUrlFilters', () => {
    it('should return parsed filters from URL search params', () => {
        const { result } = renderHookWithRouter(() => useFlowLogsUrlFilters(), {
            routes: ['/?source_name=nginx&dest_namespace=default'],
        });

        expect(result.current.filters).toEqual({
            source_name: ['nginx'],
            dest_namespace: ['default'],
        });
    });

    it('should return empty filters when there are no search params', () => {
        const { result } = renderHookWithRouter(() => useFlowLogsUrlFilters(), {
            routes: ['/'],
        });

        expect(result.current.filters).toEqual({});
    });

    describe('setFilter', () => {
        it('should add filter values to the URL', () => {
            const { result } = renderHookWithRouter(
                () => useFlowLogsUrlFilters(),
                { routes: ['/'] },
            );

            act(() => {
                result.current.setFilter('source_name', ['nginx', 'envoy']);
            });

            expect(result.current.filters).toEqual({
                source_name: ['nginx', 'envoy'],
            });
        });

        it('should replace existing values for a key', () => {
            const { result } = renderHookWithRouter(
                () => useFlowLogsUrlFilters(),
                { routes: ['/?source_name=old'] },
            );

            act(() => {
                result.current.setFilter('source_name', ['new']);
            });

            expect(result.current.filters).toEqual({
                source_name: ['new'],
            });
        });

        it('should remove a filter key when values is null', () => {
            const { result } = renderHookWithRouter(
                () => useFlowLogsUrlFilters(),
                { routes: ['/?source_name=nginx&dest_port=80'] },
            );

            act(() => {
                result.current.setFilter('source_name', null);
            });

            expect(result.current.filters).toEqual({
                dest_port: ['80'],
            });
        });

        it('should preserve other filter keys when setting a new one', () => {
            const { result } = renderHookWithRouter(
                () => useFlowLogsUrlFilters(),
                { routes: ['/?action=allow'] },
            );

            act(() => {
                result.current.setFilter('reporter', ['src']);
            });

            expect(result.current.filters).toEqual({
                action: ['allow'],
                reporter: ['src'],
            });
        });
    });

    describe('clearFilters', () => {
        it('should remove all filter keys from the URL', () => {
            const { result } = renderHookWithRouter(
                () => useFlowLogsUrlFilters(),
                {
                    routes: [
                        '/?source_name=nginx&dest_namespace=default&action=allow',
                    ],
                },
            );

            act(() => {
                result.current.clearFilters();
            });

            expect(result.current.filters).toEqual({});
        });

        it('should preserve non-filter search params', () => {
            const { result } = renderHookWithRouter(
                () => useFlowLogsUrlFilters(),
                { routes: ['/?source_name=nginx&custom_param=keep'] },
            );

            act(() => {
                result.current.clearFilters();
            });

            expect(result.current.filters).toEqual({});
        });
    });
});

describe('parseFiltersFromParams', () => {
    it('should return an empty object when there are no params', () => {
        const params = new URLSearchParams();
        expect(parseFiltersFromParams(params)).toEqual({});
    });

    it('should parse a single filter key with one value', () => {
        const params = new URLSearchParams('source_name=nginx');
        expect(parseFiltersFromParams(params)).toEqual({
            source_name: ['nginx'],
        });
    });

    it('should parse a single filter key with multiple values', () => {
        const params = new URLSearchParams(
            'dest_namespace=default&dest_namespace=kube-system',
        );
        expect(parseFiltersFromParams(params)).toEqual({
            dest_namespace: ['default', 'kube-system'],
        });
    });

    it('should parse multiple different filter keys', () => {
        const params = new URLSearchParams(
            'source_name=nginx&dest_port=80&action=allow',
        );
        expect(parseFiltersFromParams(params)).toEqual({
            source_name: ['nginx'],
            dest_port: ['80'],
            action: ['allow'],
        });
    });

    it('should ignore params that are not in filterKeys', () => {
        const params = new URLSearchParams(
            'source_name=nginx&unknown_key=value',
        );
        expect(parseFiltersFromParams(params)).toEqual({
            source_name: ['nginx'],
        });
    });

    it('should delegate the policy key to transformJSON', () => {
        const policies = JSON.stringify(['tier1|policy1', 'tier2|policy2']);
        const params = new URLSearchParams(
            `policy=${encodeURIComponent(policies)}`,
        );
        expect(parseFiltersFromParams(params)).toEqual({
            policy: ['tier1|policy1', 'tier2|policy2'],
        });
    });

    it('should handle a mix of regular and transformed keys', () => {
        const policies = JSON.stringify(['default|my-policy']);
        const params = new URLSearchParams(
            `source_namespace=prod&policy=${encodeURIComponent(policies)}&reporter=src`,
        );
        expect(parseFiltersFromParams(params)).toEqual({
            source_namespace: ['prod'],
            policy: ['default|my-policy'],
            reporter: ['src'],
        });
    });
});

describe('buildSearchParamsFromFilters', () => {
    it('should add new filter keys to empty search params', () => {
        const params = new URLSearchParams();
        const result = buildSearchParamsFromFilters(params, {
            source_name: ['nginx'],
        });
        expect(result.getAll('source_name')).toEqual(['nginx']);
    });

    it('should add multiple values for a single key', () => {
        const params = new URLSearchParams();
        const result = buildSearchParamsFromFilters(params, {
            dest_namespace: ['default', 'kube-system'],
        });
        expect(result.getAll('dest_namespace')).toEqual([
            'default',
            'kube-system',
        ]);
    });

    it('should replace existing values for a key', () => {
        const params = new URLSearchParams('source_name=old');
        const result = buildSearchParamsFromFilters(params, {
            source_name: ['new'],
        });
        expect(result.getAll('source_name')).toEqual(['new']);
    });

    it('should remove a key when values is null', () => {
        const params = new URLSearchParams('source_name=nginx&dest_port=80');
        const result = buildSearchParamsFromFilters(params, {
            source_name: null,
        });
        expect(result.has('source_name')).toBe(false);
        expect(result.getAll('dest_port')).toEqual(['80']);
    });

    it('should preserve params not mentioned in filters', () => {
        const params = new URLSearchParams('action=allow&reporter=src');
        const result = buildSearchParamsFromFilters(params, {
            action: ['deny'],
        });
        expect(result.getAll('action')).toEqual(['deny']);
        expect(result.getAll('reporter')).toEqual(['src']);
    });

    it('should preserve non-filter search params', () => {
        const params = new URLSearchParams(
            'source_name=nginx&custom_param=keep',
        );
        const result = buildSearchParamsFromFilters(params, {
            source_name: null,
        });
        expect(result.has('source_name')).toBe(false);
        expect(result.getAll('custom_param')).toEqual(['keep']);
    });

    it('should handle multiple keys at once', () => {
        const params = new URLSearchParams('source_name=old&dest_port=80');
        const result = buildSearchParamsFromFilters(params, {
            source_name: ['new'],
            dest_port: null,
            action: ['allow'],
        });
        expect(result.getAll('source_name')).toEqual(['new']);
        expect(result.has('dest_port')).toBe(false);
        expect(result.getAll('action')).toEqual(['allow']);
    });

    it('should not mutate the original search params', () => {
        const params = new URLSearchParams('source_name=nginx');
        buildSearchParamsFromFilters(params, {
            source_name: ['envoy'],
        });
        expect(params.getAll('source_name')).toEqual(['nginx']);
    });

    it('should handle an empty filters object', () => {
        const params = new URLSearchParams('source_name=nginx');
        const result = buildSearchParamsFromFilters(params, {});
        expect(result.getAll('source_name')).toEqual(['nginx']);
    });

    it('should remove a key when values is an empty array', () => {
        const params = new URLSearchParams('source_name=nginx');
        const result = buildSearchParamsFromFilters(params, {
            source_name: [],
        });
        expect(result.has('source_name')).toBe(false);
    });
});

describe('transformJSON', () => {
    it('should parse a valid JSON array string', () => {
        const input = JSON.stringify(['tier1|policy1', 'tier2|policy2']);
        expect(transformJSON.policy!(input)).toEqual([
            'tier1|policy1',
            'tier2|policy2',
        ]);
    });

    it('should return an empty array for an empty JSON array', () => {
        expect(transformJSON.policy!('[]')).toEqual([]);
    });

    it('should return an empty array for invalid JSON', () => {
        expect(transformJSON.policy!('not-json')).toEqual([]);
    });

    it('should return an empty array for an empty string', () => {
        expect(transformJSON.policy!('')).toEqual([]);
    });

    it('should parse a JSON object without error', () => {
        const result = transformJSON.policy!('{"key":"value"}');
        expect(result).toEqual({ key: 'value' });
    });
});
