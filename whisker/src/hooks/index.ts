import React from 'react';
import { useSelectedListOmniFilters } from './omniFilters';
import { useAppConfig } from '@/context/AppConfig';
import { version } from '../../package.json';

const DEBOUNCE_TIME = 500;

export const useDebouncedCallback = () => {
    const [debouncedValue, setDebouncedValue] = React.useState<null | string>(
        null,
    );
    const callback = React.useRef<() => void>(() => undefined);
    const handler = React.useRef<any>(null);

    React.useEffect(() => {
        if (callback.current) {
            handler.current = setTimeout(() => {
                callback.current();
            }, DEBOUNCE_TIME);

            return () => {
                clearTimeout(handler.current);
            };
        }
    }, [debouncedValue]);

    return (value: string | null, debouncedFn: () => void) => {
        setDebouncedValue(value);
        callback.current = debouncedFn;
    };
};

export const useClusterId = () => useAppConfig()?.config.cluster_id;

export const useFeature = (feature: string) =>
    useAppConfig()?.features?.[feature] === true;

export const useBuildInfo = () => {
    React.useEffect(() => {
        console.groupCollapsed('Build information');
        console.info(`version = ${version}`);
        console.groupEnd();
    }, []);
};

export { useSelectedListOmniFilters };
