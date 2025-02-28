import { objToQueryStr, QueryObject } from '@/libs/tigera/ui-components/utils';
import { ApiError, UseStreamResult } from '@/types/api';
import { createEventSource } from '@/utils';
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

export const useStream = <T>(path: string): UseStreamResult<T> => {
    const [data, setData] = React.useState<any[]>([]);
    const [error, setError] = React.useState<ApiError | null>(null);
    const [isDataStreaming, setIsDataStreaming] = React.useState(false);
    const [hasStoppedStreaming, setHasStoppedStreaming] = React.useState(false);
    const [isStreamOpen, setIsStreamOpen] = React.useState(false);

    const eventSourceRef = React.useRef<null | EventSource>(null);

    const startStream = React.useCallback(
        (updatedPath?: string) => {
            setError(null);
            setHasStoppedStreaming(false);

            if (!eventSourceRef.current) {
                console.info('creating new event stream');
                eventSourceRef.current = createEventSource(updatedPath ?? path);
            } else {
                console.info('restarting event stream');
                eventSourceRef.current.close();
                eventSourceRef.current = createEventSource(updatedPath ?? path);
            }

            const eventSource = eventSourceRef.current as EventSource;

            eventSource.onopen = () => {
                setIsStreamOpen(true);
            };

            eventSource.onmessage = (event) => {
                setIsDataStreaming(true);
                const stream = JSON.parse(event.data);
                console.info({ event });
                setData((list) => [stream, ...list]);
            };

            eventSource.onerror = (error) => {
                setIsDataStreaming(false);
                setIsStreamOpen(false);
                console.error({ error });
                setError({});
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

        return () => stopStream();
    }, []);

    return {
        data,
        error,
        startStream,
        stopStream,
        isDataStreaming,
        isWaiting: isStreamOpen && !isDataStreaming,
        hasStoppedStreaming,
    };
};

export default {
    get,
    useStream,
};
