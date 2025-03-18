import api, { useStream } from '@/api';
import { useDidUpdate } from '@/libs/tigera/ui-components/hooks';
import { objToQueryStr } from '@/libs/tigera/ui-components/utils';
import { ApiFilterResponse, FlowLog, QueryPage } from '@/types/api';
import {
    FilterHintTypes,
    ListOmniFilterParam,
    OmniFilterParam,
    OmniFilterProperties,
    transformToFlowsFilterQuery,
    transformToQueryPage,
    FilterHintType,
} from '@/utils/omniFilter';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';

const getFlowLogs = (queryParams?: Record<string, string>) =>
    api.get<FlowLog[]>('flows', {
        queryParams,
    });

export const useFlowLogs = (queryParams?: Record<string, string>) =>
    useQuery({
        queryKey: ['flowLogs', queryParams],
        queryFn: () => getFlowLogs(queryParams),
    });

export const useDeniedFlowLogsCount = () => {
    return useFlowLogsCount({ action: 'deny' });
};

export const useFlowLogsCount = (queryParams?: Record<string, string>) => {
    const { data: count } = useQuery({
        queryKey: ['flowLogsCount'],
        queryFn: () => getFlowLogs(queryParams),
        select: (data) => data.length, // todo: maybe stats api
    });

    return count;
};

export const fetchFilters = (query: {
    type: FilterHintType;
    limit: number;
    page: number;
    filters?: string;
}): Promise<ApiFilterResponse> =>
    api.get('flows-filter-hints', {
        queryParams: query,
    });

export const useInfiniteFilterQuery = (
    filterParam: ListOmniFilterParam,
    query: string | null,
) =>
    useInfiniteQuery<QueryPage, any>({
        queryKey: [filterParam, query],
        initialPageParam: 1,
        queryFn: ({ pageParam }) =>
            fetchFilters({
                page: pageParam as number,
                type: FilterHintTypes[filterParam],
                limit: OmniFilterProperties[filterParam].limit!,
                filters: query ?? undefined,
            }).then((response) =>
                transformToQueryPage(response, pageParam as number),
            ),
        getNextPageParam: (lastPage) => lastPage.nextPage,
        enabled: query !== null,
    });

export const useFlowLogsStream = (
    filterValues: Record<OmniFilterParam, string[]>,
) => {
    const filters = transformToFlowsFilterQuery(filterValues);
    const queryString = objToQueryStr({
        watch: true,
        filters,
    });
    const path = `flows${queryString}`;
    const { startStream, ...rest } = useStream<FlowLog>(path);

    useDidUpdate(() => {
        startStream(path);
    }, [filters]);

    return { startStream, ...rest };
};
