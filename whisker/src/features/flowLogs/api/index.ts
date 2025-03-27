import api, { useStream } from '@/api';
import { useDidUpdate } from '@/libs/tigera/ui-components/hooks';
import {
    ApiFilterResponse,
    FlowLog as ApiFlowLog,
    QueryPage,
} from '@/types/api';
import { FlowLog } from '@/types/render';
import {
    FilterHintType,
    FilterHintTypes,
    FilterKey,
    ListOmniFilterParam,
    OmniFilterProperties,
    transformToFlowsFilterQuery,
    transformToQueryPage,
} from '@/utils/omniFilter';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import React from 'react';
import {
    buildStreamPath,
    getTimeInSeconds,
    transformFlowLogsResponse,
} from '../utils';

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
    pageSize: number;
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
        initialPageParam: 0,
        queryFn: ({ pageParam }) =>
            fetchFilters({
                page: pageParam as number,
                type: FilterHintTypes[filterParam],
                pageSize: OmniFilterProperties[filterParam].limit!,
                filters: query ?? undefined,
            }).then((response) =>
                transformToQueryPage(response, pageParam as number),
            ),
        getNextPageParam: (lastPage) => lastPage.nextPage,
        enabled: query !== null,
    });

const STREAM_TIME_OFFSET = -300;

export const useFlowLogsStream = (
    filterValues: Partial<Record<FilterKey, string[]>>,
) => {
    const initialStreamStartTime = React.useRef<number | null>(null);
    const filters = transformToFlowsFilterQuery(
        filterValues as Record<FilterKey, string[]>,
    );
    const path = buildStreamPath(STREAM_TIME_OFFSET, filters);

    const { startStream, data, ...rest } = useStream<ApiFlowLog, FlowLog>({
        path,
        transformResponse: transformFlowLogsResponse,
    });

    // First flow start time is needed for accurate filtering
    React.useEffect(() => {
        if (initialStreamStartTime.current === null && data.length > 0) {
            const sorted = data.sort(
                (a, b) => b.start_time.getTime() - a.start_time.getTime(),
            );
            initialStreamStartTime.current =
                sorted[data.length - 1].start_time.getTime();
        }
    }, [data.length]);

    useDidUpdate(() => {
        const startTimeGte = getTimeInSeconds(initialStreamStartTime.current);
        const path = buildStreamPath(startTimeGte, filters);
        startStream({
            path,
            isUpdate: true,
        });
    }, [filters]);

    const start = () => {
        const path = buildStreamPath(
            getTimeInSeconds(data[0]?.start_time.getTime()),
            filters,
        );
        startStream({ path });
    };

    return { startStream: start, data, ...rest };
};
