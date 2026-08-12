import { parseStartTime } from '@/utils';
import {
    OmniFilterProperties,
    SelectedOmniFilterValues,
    UrlFilterKey,
    urlFilterKeys,
} from '@/utils/omniFilter';
import { useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';

export type { UrlFilterKey };

export const parseFiltersFromParams = (
    searchParams: URLSearchParams,
): SelectedOmniFilterValues => {
    const filters: SelectedOmniFilterValues = {};

    for (const key of urlFilterKeys) {
        const values = searchParams.getAll(key);

        if (values.length) {
            const { parseUrlValue } = OmniFilterProperties[key];
            (filters as Record<UrlFilterKey, unknown>)[key] = parseUrlValue
                ? parseUrlValue(values[0])
                : values;
        }
    }

    return filters;
};

export const buildSearchParamsFromFilters = (
    searchParams: URLSearchParams,
    filters: Partial<Record<string, string[] | null>>,
): URLSearchParams => {
    const next = new URLSearchParams(searchParams);

    for (const [key, values] of Object.entries(filters)) {
        next.delete(key);

        if (values != null) {
            for (const value of values) {
                next.append(key, value);
            }
        }
    }

    return next;
};

export const useFlowLogsUrlFilters = () => {
    const [searchParams, setSearchParams] = useSearchParams();

    const filters = useMemo(
        () => parseFiltersFromParams(searchParams),
        [searchParams.toString()],
    );

    const startTime = parseStartTime(filters.start_time?.[0]);

    const filterHintValues = useMemo(() => {
        const { start_time: _startTime, ...rest } = filters;
        return rest;
    }, [filters]);

    const setMultiFilter = (
        filters: Partial<Record<UrlFilterKey, string[] | null>>,
    ) => {
        setSearchParams(buildSearchParamsFromFilters(searchParams, filters));
    };

    const setFilter = (key: string, values: string[] | null) => {
        setMultiFilter({ [key]: values } as Partial<
            Record<UrlFilterKey, string[] | null>
        >);
    };

    const clearFilters = () => {
        const nulled = Object.fromEntries(
            urlFilterKeys.map((key) => [key, null]),
        );
        setSearchParams(buildSearchParamsFromFilters(searchParams, nulled));
    };

    return {
        filters,
        startTime,
        filterHintValues,
        setFilter,
        setMultiFilter,
        clearFilters,
    };
};
