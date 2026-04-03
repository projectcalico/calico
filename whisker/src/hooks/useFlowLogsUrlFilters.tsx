import { useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';

const filterKeys = [
    'source_name',
    'source_namespace',
    'dest_name',
    'dest_namespace',
    'policy',
    'dest_port',
    'protocol',
    'action',
    'staged_action',
    'pending_action',
    'reporter',
    'start_time',
] as const;

type FilterKey = (typeof filterKeys)[number];

export const transformJSON: Partial<Record<FilterKey, (value: string) => []>> =
    {
        policy: (value: string) => {
            try {
                return JSON.parse(value);
            } catch {
                return [];
            }
        },
    };

type Filters = Partial<Record<FilterKey, string[]>>;

export const parseFiltersFromParams = (
    searchParams: URLSearchParams,
): Filters => {
    const filters: Filters = {};

    for (const key of filterKeys) {
        const values = searchParams.getAll(key);

        if (values.length) {
            if (transformJSON[key]) {
                filters[key] = transformJSON[key](values[0]);
            } else {
                filters[key] = values;
            }
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

    const setMultiFilter = (
        filters: Partial<Record<FilterKey, string[] | null>>,
    ) => {
        setSearchParams(buildSearchParamsFromFilters(searchParams, filters));
    };

    const setFilter = (key: string, values: string[] | null) => {
        setMultiFilter({ [key]: values } as Partial<
            Record<FilterKey, string[] | null>
        >);
    };

    const clearFilters = () => {
        const nulled = Object.fromEntries(filterKeys.map((key) => [key, null]));
        setSearchParams(buildSearchParamsFromFilters(searchParams, nulled));
    };

    return {
        filters,
        setFilter,
        setMultiFilter,
        clearFilters,
    };
};
