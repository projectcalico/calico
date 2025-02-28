import React from 'react';
import { useSelectedOmniFilters } from './omniFilters';
import { SelectedOmniFilters } from '@/utils/omniFilter';
import { FlowLogsQuery } from '@/types/api';

const DEBOUNCE_TIME = 300;

export const useDebounce = (value: string | undefined) => {
    const [debouncedValue, setDebouncedValue] = React.useState(value);

    React.useEffect(() => {
        const handler = setTimeout(() => {
            setDebouncedValue(value);
        }, DEBOUNCE_TIME);

        return () => {
            clearTimeout(handler);
        };
    }, [value]);

    return debouncedValue;
};

export const useFlowLogsQueryParams = (filters: SelectedOmniFilters): string =>
    JSON.stringify({
        src_namespace: filters.namespace,
        dst_namespace: filters.namespace,
        src_name: filters.src_name,
        dst_name: filters.dst_name,
        ...(filters.policy && {
            policy: {
                properties: {
                    name: filters.policy,
                },
            },
        }),
    } satisfies FlowLogsQuery);

export { useSelectedOmniFilters };
