import React from 'react';
import { useSelectedOmniFilters } from './omniFilters';

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

export { useSelectedOmniFilters };
