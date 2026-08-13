import {
    FlowsFilter,
    FlowsFilterKeys,
    FlowsFilterQuery,
    PolicyFilterQuery,
} from '@/types/api';
import { dataFilters, DataFilterId } from './dataFilters';
import { PolicyFilter } from './types';
import { SelectedOmniFilterValues, UrlFilterKey } from './urlKeys';

export type FlowsFilterId = Exclude<UrlFilterKey, 'start_time'>;

const flowsFilterSpec = <K extends FlowsFilterKeys, V>(
    flowsFilterKey: K,
    toFilterValue: (values: V[]) => FlowsFilter[K] | undefined,
) => ({ flowsFilterKey, toFilterValue });

const handleEmptyFilters = <T>(filters: T[]) =>
    filters.length ? filters : undefined;

const exactMatch = (value: string | number): FlowsFilterQuery => ({
    type: 'Exact',
    value,
});

export const transformToExactMatches = (values: string[] = []) =>
    handleEmptyFilters(values.map(exactMatch));

export const transformToPortMatches = (values: string[]) =>
    handleEmptyFilters(values.map(Number).filter(Boolean).map(exactMatch));

export const transformToHeadValue = (values: string[]) => values[0];

export const transformToHeadList = (values: string[]) => [values[0]];

export const transformToPolicyMatches = (
    values: PolicyFilter[],
): PolicyFilterQuery[] =>
    values.map(({ name, namespace, tier, kind }) => ({
        ...(name && { name: exactMatch(name) }),
        ...(namespace && { namespace: exactMatch(namespace) }),
        ...(tier && { tier: exactMatch(tier) }),
        ...(kind && { kind }),
    }));

export const flowLogFilterMap = {
    policy: flowsFilterSpec('policies', transformToPolicyMatches),
    source_namespace: flowsFilterSpec(
        'source_namespaces',
        transformToExactMatches,
    ),
    source_name: flowsFilterSpec('source_names', transformToExactMatches),
    dest_namespace: flowsFilterSpec('dest_namespaces', transformToExactMatches),
    dest_name: flowsFilterSpec('dest_names', transformToExactMatches),
    reporter: flowsFilterSpec('reporter', transformToHeadValue),
    dest_port: flowsFilterSpec('dest_ports', transformToPortMatches),
    protocol: flowsFilterSpec('protocols', transformToExactMatches),
    action: flowsFilterSpec('actions', transformToHeadList),
    staged_action: flowsFilterSpec('pending_actions', transformToHeadList),
} satisfies Record<FlowsFilterId, unknown>;

type ErasedSpec = {
    flowsFilterKey: FlowsFilterKeys;
    toFilterValue: (values: never[]) => unknown;
};

const toFlowLogFilter = (
    omniFilterValues: SelectedOmniFilterValues,
    excludeId?: DataFilterId,
): FlowsFilter =>
    Object.entries(omniFilterValues).reduce<FlowsFilter>(
        (acc, [key, values]) => {
            const spec: ErasedSpec | undefined =
                flowLogFilterMap[key as FlowsFilterId];

            if (
                !spec ||
                key === excludeId ||
                values === undefined ||
                values.length === 0
            ) {
                return acc;
            }

            return {
                ...acc,
                [spec.flowsFilterKey]: spec.toFilterValue(values as never[]),
            };
        },
        {},
    );

const toQueryString = (filters: FlowsFilter) =>
    Object.keys(filters).length ? JSON.stringify(filters) : '';

export const toFlowLogFilterQuery = (
    omniFilterValues: SelectedOmniFilterValues,
): string => toQueryString(toFlowLogFilter(omniFilterValues));

export const toDataFilterQuery = (
    omniFilterValues: SelectedOmniFilterValues,
    filterId: DataFilterId,
    searchInput?: string,
): string => {
    const narrowingContext = toFlowLogFilter(omniFilterValues, filterId);

    return toQueryString(
        searchInput
            ? {
                  ...narrowingContext,
                  ...dataFilters[filterId].toSearch(searchInput),
              }
            : narrowingContext,
    );
};
