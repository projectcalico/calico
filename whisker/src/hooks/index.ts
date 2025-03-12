import React from 'react';
import { useSelectedOmniFilters } from './omniFilters';
import { SelectedOmniFilters } from '@/utils/omniFilter';
import { FlowLogsQuery } from '@/types/api';

const DEBOUNCE_TIME = 300;

export const useDebouncedCallback = () => {
    const [debouncedValue, setDebouncedValue] = React.useState<null | string>(
        null,
    );
    const callback = React.useRef<() => void>(() => undefined);

    React.useEffect(() => {
        if (debouncedValue !== null && callback.current) {
            const handler = setTimeout(() => {
                callback.current();
            }, DEBOUNCE_TIME);

            return () => {
                clearTimeout(handler);
            };
        }
    }, [debouncedValue]);

    return (value: string, debouncedFn: () => void) => {
        setDebouncedValue(value);
        callback.current = debouncedFn;
    };
};

export const useFlowLogsQueryParams = (filters: SelectedOmniFilters): string =>
    JSON.stringify({
        source_namespace: filters.source_namespace,
        dest_namespace: filters.dest_namespace,
        source_name: filters.source_name,
        dest_name: filters.dest_name,
        ...(filters.policy && {
            policy: {
                name: filters.policy,
            },
        }),
    } satisfies FlowLogsQuery);

export { useSelectedOmniFilters };
