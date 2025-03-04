import api, { useStream } from '@/api';
import { useDebounce, useFlowLogsQueryParams } from '@/hooks';
import { useDidUpdate } from '@/libs/tigera/ui-components/hooks';
import {
    ApiFilterResponse,
    FlowLog,
    OmniFilterDataQuery,
    QueryPage,
} from '@/types/api';
import {
    OmniFilterParam,
    SelectedOmniFilters,
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

export const fetchFilters = ({
    page,
    searchOption,
    filterParam,
}: OmniFilterDataQuery): Promise<ApiFilterResponse> =>
    api.get(`filters/${filterParam}`, {
        queryParams: { page, searchOption },
    });

export const useInfiniteFilterQuery = (
    filterParam: OmniFilterParam,
    query: OmniFilterDataQuery | null,
) => {
    const debouncedSearch = useDebounce(query?.searchOption ?? '');

    return useInfiniteQuery<QueryPage, any>({
        queryKey: [filterParam, debouncedSearch],
        initialPageParam: 1,
        queryFn: ({ pageParam }) =>
            fetchFilters({
                filterParam,
                page: pageParam as number,
                searchOption: query?.searchOption ?? '',
            }).then((response) =>
                transformToQueryPage(response, pageParam as number),
            ),
        getNextPageParam: (lastPage) => lastPage.nextPage,
        enabled: query !== null,
    });
};

export const useFlowLogsStream = (filters: SelectedOmniFilters) => {
    const query = useFlowLogsQueryParams(filters);
    const path = `flows?watch=true&query=${query}`;
    const { startStream, ...rest } = useStream<FlowLog>(path);

    useDidUpdate(() => {
        startStream(path);
    }, [query]);

    return { startStream, ...rest };
};
