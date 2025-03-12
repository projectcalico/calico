import api, { useStream } from '@/api';
import { useDidUpdate } from '@/libs/tigera/ui-components/hooks';
import { ApiFilterResponse, FlowLog, QueryPage } from '@/types/api';
import {
    OmniFilterParam,
    OmniFilterProperties,
    transformToFlowsFilterQuery,
    transformToQueryPage,
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
    filter_type: OmniFilterParam;
    limit: number;
    page: number;
    filters?: string;
}): Promise<ApiFilterResponse> =>
    api.get('flows-filter-hints', {
        queryParams: query,
    });

export const useInfiniteFilterQuery = (
    filterParam: OmniFilterParam,
    query: string | null,
) => {
    const debouncedSearch = query ?? '';

    return useInfiniteQuery<QueryPage, any>({
        queryKey: [filterParam, debouncedSearch],
        initialPageParam: 1,
        queryFn: ({ pageParam }) =>
            fetchFilters({
                page: pageParam as number,
                filter_type: filterParam,
                limit: OmniFilterProperties[filterParam].limit,
                filters: query ?? undefined,
            }).then((response) =>
                transformToQueryPage(response, pageParam as number),
            ),
        getNextPageParam: (lastPage) => lastPage.nextPage,
        enabled: query !== null && debouncedSearch.length >= 1,
    });
};

export const useFlowLogsStream = (
    filters: Record<OmniFilterParam, string[]>,
) => {
    const query = transformToFlowsFilterQuery(filters);
    const path = `flows?watch=true&query=${query}`;
    const { startStream, ...rest } = useStream<FlowLog>(path);

    useDidUpdate(() => {
        startStream(path);
    }, [query]);

    return { startStream, ...rest };
};
