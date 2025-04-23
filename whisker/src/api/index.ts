import { objToQueryStr, QueryObject } from '@/libs/tigera/ui-components/utils';
import {
    ApiError,
    StartStreamOptions,
    UseStreamOptions,
    UseStreamResult,
} from '@/types/api';
import { AppConfig } from '@/types/render';
import { createEventSource } from '@/utils';
import { useQuery } from '@tanstack/react-query';
import React from 'react';

export const API_URL = process.env.APP_API_URL;

type ApiOptions = RequestInit & {
    queryParams?: QueryObject;
};

export const apiFetch = async <T>(
    path: string,
    { queryParams, ...options }: ApiOptions = {},
): Promise<T> => {
    try {
        let queryString = '';
        if (queryParams) {
            queryString = objToQueryStr(queryParams);
        }

        const response = await fetch(
            `${API_URL}/${path}${queryString}`,
            options,
        );

        if (response.ok) {
            return await response.json();
        } else {
            const apiError: ApiError = {
                data: await response.json(),
                response,
            };
            console.error('Error response returned from api', apiError);

            return Promise.reject(apiError);
        }
    } catch (error) {
        console.error('Error sending http request', error);
        return Promise.reject({});
    }
};

const get = <T>(path: string, options: ApiOptions = {}): Promise<T> => {
    return apiFetch(path, { method: 'get', ...options });
};

const STREAM_THROTTLE = 1000;
const MAX_FETCHING_TIMEOUT = 5000;

export const useStream = <S, R>({
    path,
    transformResponse,
}: UseStreamOptions<S, R>): UseStreamResult<R> => {
    const [data, setData] = React.useState<any[]>([]);
    const [error, setError] = React.useState<ApiError | null>(null);
    const [isDataStreaming, setIsDataStreaming] = React.useState(false);
    const [hasStoppedStreaming, setHasStoppedStreaming] = React.useState(false);
    const [isStreamOpen, setIsStreamOpen] = React.useState(false);
    const [isFetching, setIsFetching] = React.useState(false);

    const eventSourceRef = React.useRef<null | EventSource>(null);
    const buffer = React.useRef<any[]>([]);
    const timer = React.useRef<any>(null);
    const hasTimeout = React.useRef(false);
    const hasReplacedStream = React.useRef(false);
    const isFetchingTimeout = React.useRef<NodeJS.Timeout | null>(null);

    const startStream = React.useCallback(
        (options: StartStreamOptions = {}) => {
            setError(null);
            setHasStoppedStreaming(false);
            setIsFetching(options.isUpdate || false);
            hasReplacedStream.current = false;
            clearTimeout(timer.current);
            hasTimeout.current = false;

            if (options.isUpdate) {
                setData([]);
            }

            if (!eventSourceRef.current) {
                console.info('creating new event stream');
                eventSourceRef.current = createEventSource(
                    options.path ?? path,
                );
            } else {
                console.info('restarting event stream');
                eventSourceRef.current.close();
                eventSourceRef.current = createEventSource(
                    options.path ?? path,
                );
            }

            const eventSource = eventSourceRef.current as EventSource;

            if (isFetchingTimeout.current) {
                clearTimeout(isFetchingTimeout.current);
                isFetchingTimeout.current = null;
            }

            if (!isFetchingTimeout.current) {
                isFetchingTimeout.current = setTimeout(() => {
                    setIsFetching(false);
                }, MAX_FETCHING_TIMEOUT);
            }

            eventSource.onopen = () => {
                setIsStreamOpen(true);
                clearTimeout(timer.current ?? '');
            };

            eventSource.onmessage = (event) => {
                setIsDataStreaming(true);
                const stream = JSON.parse(event.data);

                buffer.current.push(transformResponse(stream));

                if (!hasTimeout.current) {
                    hasTimeout.current = true;
                    timer.current = setTimeout(() => {
                        setIsFetching(false);
                        const bufferedData = [...buffer.current];
                        if (options.isUpdate && !hasReplacedStream.current) {
                            setData(bufferedData);
                            hasReplacedStream.current = true;
                        } else {
                            setData((list) => [...bufferedData, ...list]);
                        }

                        buffer.current = [];
                        hasTimeout.current = false;
                    }, STREAM_THROTTLE);
                }
            };

            eventSource.onerror = (error) => {
                setIsDataStreaming(false);
                setIsStreamOpen(false);
                setIsFetching(false);
                console.error({ error });
                setError({});
                clearTimeout(timer.current ?? '');
                eventSource.close();
            };
        },
        [eventSourceRef.current],
    );

    const stopStream = React.useCallback(() => {
        if (eventSourceRef.current) {
            console.info('closing stream function');
            eventSourceRef.current.close();
        }
        setIsDataStreaming(false);
        setIsStreamOpen(false);
        setHasStoppedStreaming(true);
    }, [eventSourceRef.current]);

    React.useEffect(() => {
        console.info('setting up stream');
        startStream();

        return () => {
            clearTimeout(timer.current ?? '');
            clearTimeout(isFetchingTimeout.current ?? '');
            stopStream();
        };
    }, []);

    return {
        data,
        error,
        startStream,
        stopStream,
        isDataStreaming,
        isWaiting: isStreamOpen && !isDataStreaming,
        hasStoppedStreaming,
        isFetching,
    };
};

export const useAppConfigQuery = () =>
    useQuery<AppConfig>({
        queryKey: ['config'],
        queryFn: () =>
            fetch(process.env.APP_CONFIG_PATH).then((response) =>
                response.json(),
            ),
    });

export default {
    get,
    useStream,
};
