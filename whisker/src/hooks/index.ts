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
