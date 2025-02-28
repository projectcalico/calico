import React from 'react';
import { useSelectedOmniFilters } from './omniFilters';

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

export { useSelectedOmniFilters };
