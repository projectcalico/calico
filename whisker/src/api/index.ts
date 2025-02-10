import { objToQueryStr, QueryObject } from '@/libs/tigera/ui-components/utils';
import { ApiError } from '@/types/api';
import React from 'react';
import { createEventSource } from '@/utils';

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

export type UseStreamResult<T> = {
    data: T[];
    error: ApiError | null;
    startStream: () => void;
    stopStream: () => void;
    isStreaming: boolean;
    isFetching: boolean;
};

export const useStream = <T>(path: string): UseStreamResult<T> => {
    const [data, setData] = React.useState<any[]>([]);
    const [error, setError] = React.useState<ApiError | null>(null);
    const [isStreaming, setIsStreaming] = React.useState(false);
    const [isFetching, setIsFetching] = React.useState(false);
    const eventSourceRef = React.useRef<null | EventSource>(null);

    const startStream = React.useCallback(() => {
        setIsStreaming(true);
        setIsFetching(true);
        setError(null);

        if (!eventSourceRef.current) {
            console.info('creating new event stream');
            eventSourceRef.current = createEventSource(path);
        } else {
            console.info('restarting event stream');
            eventSourceRef.current.close();
            eventSourceRef.current = createEventSource(path);
        }

        const eventSource = eventSourceRef.current as EventSource;

        eventSource.onmessage = (event) => {
            setIsFetching(false);
            const stream = JSON.parse(event.data);
            console.info({ event });
            setData((list) => [stream, ...list]);
        };

        eventSource.onerror = (error) => {
            setIsFetching(false);
            console.error({ error });
            setError({});
            eventSource.close();
        };
    }, [eventSourceRef.current]);

    const stopStream = React.useCallback(() => {
        if (eventSourceRef.current) {
            console.info('closing stream function');
            eventSourceRef.current.close();
        }
        setIsStreaming(false);
    }, [eventSourceRef.current]);

    React.useEffect(() => {
        console.info('setting up stream');
        startStream();

        return () => stopStream();
    }, []);

    return {
        data,
        error,
        startStream,
        stopStream,
        isStreaming,
        isFetching,
    };
};

export default {
    get,
    useStream,
};
