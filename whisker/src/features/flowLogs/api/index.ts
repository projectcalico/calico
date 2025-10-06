import api, { useStream } from '@/api';
import { useDidUpdate } from '@/libs/tigera/ui-components/hooks';
import {
    ApiFilterResponse,
    FlowLog as ApiFlowLog,
    QueryPage,
} from '@/types/api';
import { FilterHintValues, FlowLog, UniqueFlowLogs } from '@/types/render';
import {
    FilterHintKey,
    FilterHintType,
    FilterHintTypes,
    OmniFilterProperties,
    transformToFlowsFilterQuery,
    transformToQueryPage,
} from '@/utils/omniFilter';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import React from 'react';
import {
    buildStreamPath,
    getTimeInSeconds,
    handleDuplicateFlowLogs,
    transformFlowLogsResponse,
    transformStartTime,
    updateFirstFlowStartTime,
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
    filterParam: FilterHintKey,
    query: string | null,
) =>
    useInfiniteQuery<QueryPage, any>({
        queryKey: [filterParam, query],
        initialPageParam: 0,
        queryFn: ({ pageParam }) =>
            fetchFilters({
                page: pageParam as number,
                type: FilterHintTypes[filterParam],
                pageSize: OmniFilterProperties[filterParam].limit! ?? 1,
                filters: query ?? undefined,
            }).then((response) =>
                transformToQueryPage(response, pageParam as number),
            ),
        getNextPageParam: (lastPage) => lastPage.nextPage,
        enabled: query !== null,
    });

export const useFlowLogsStream = (
    startTime: number,
    filterHintValues: Partial<FilterHintValues>,
) => {
    const firstFlowStartTime = React.useRef<number | null>(null);
    const restartTime = React.useRef<number | null>(null);
    const filters = transformToFlowsFilterQuery(
        filterHintValues as FilterHintValues,
    );
    const startTimeGte = transformStartTime(startTime);
    const path = buildStreamPath(startTimeGte, filters);
    const uniqueFlowLogs = React.useRef<UniqueFlowLogs>({
        startTime: 0,
        flowLogs: [],
    });

    const { startStream, data, totalItems, ...rest } = useStream<
        ApiFlowLog,
        FlowLog
    >({
        path,
        transformResponse: (stream) => {
            const transformed = transformFlowLogsResponse(stream);

            const { flowLog, flowLogs, startTime } = handleDuplicateFlowLogs({
                flowLog: transformed,
                ...uniqueFlowLogs.current,
            });

            uniqueFlowLogs.current = {
                startTime,
                flowLogs,
            };

            return flowLog;
        },
    });

    // First flow start time is needed for accurate filtering
    React.useEffect(() => {
        updateFirstFlowStartTime(
            data,
            firstFlowStartTime.current,
            (startTime) => {
                firstFlowStartTime.current = startTime;
            },
        );

        if (data.length > 0) {
            restartTime.current = data[0].end_time.getTime();
        }
    }, [totalItems]);

    const updateStream = React.useCallback(
        (path: string) => {
            startStream({
                path,
                isUpdate: true,
            });
        },
        [startStream],
    );

    useDidUpdate(() => {
        const path = buildStreamPath(
            getTimeInSeconds(firstFlowStartTime.current),
            filters,
        );
        updateStream(path);
    }, [filters, updateStream]);

    useDidUpdate(() => {
        // set first flow start time to null when the start time filter changes. It will be set to the first flow start time when the stream starts again.
        firstFlowStartTime.current = null;
        updateStream(buildStreamPath(startTimeGte, filters));
    }, [startTime, updateStream]);

    const start = () => {
        const path = buildStreamPath(
            getTimeInSeconds(restartTime.current),
            filters,
        );

        startStream({ path });
    };

    return { startStream: start, data, totalItems, ...rest };
};
