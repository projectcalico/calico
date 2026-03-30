import { SelectOption } from '@/libs/tigera/ui-components/components/common/Select';
import { PolicyFilter } from '..';
import { PolicyQuery, QuerySelect } from '../QueryList';

export const transformToQueries = (selectedValues: PolicyFilter[]) => {
    const queries = selectedValues.map((value) => ({
        ...(value.kind && { kind: { label: value.kind, value: value.kind } }),
        ...(value.tier && { tier: { label: value.tier, value: value.tier } }),
        ...(value.namespace && {
            namespace: { label: value.namespace, value: value.namespace },
        }),
        ...(value.name && { name: { label: value.name, value: value.name } }),
    }));

    return queries.length ? queries : [{}];
};

export const transformToFilterOptions = (queryState: PolicyQuery[]) => {
    console.log({ queryState });
    return queryState
        .map((query) =>
            Object.fromEntries(
                Object.entries(query).map(([key, value]) => [
                    key,
                    value?.value,
                ]),
            ),
        )
        .filter((obj) => Object.keys(obj).length > 0);
};

export const isQueryEmpty = (query: QuerySelect) =>
    Object.values(query).every((v) => !v);

export const updateQueryField = (
    queries: QuerySelect[],
    index: number,
    field: keyof QuerySelect,
    changedValue: SelectOption | null,
): QuerySelect[] =>
    queries.map((q, i) => {
        if (i !== index) return q;
        if (changedValue === null) {
            const { [field]: _, ...rest } = q;
            return rest;
        }
        return { ...q, [field]: changedValue };
    });

export const getDefaultExpanded = (queries: QuerySelect[]): string => {
    const lastQuery = queries[queries.length - 1];
    return lastQuery && isQueryEmpty(lastQuery)
        ? String(queries.length - 1)
        : '';
};
