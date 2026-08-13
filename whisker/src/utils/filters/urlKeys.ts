import { PolicyFilter } from './types';

export const urlFilterKeys = [
    'policy',
    'source_namespace',
    'source_name',
    'dest_namespace',
    'dest_name',
    'reporter',
    'dest_port',
    'protocol',
    'action',
    'staged_action',
    'start_time',
] as const;

export type UrlFilterKey = (typeof urlFilterKeys)[number];

export const FilterKeys = Object.fromEntries(
    urlFilterKeys.map((key) => [key, key]),
) as { [K in UrlFilterKey]: K };

export type SelectedOmniFilterValues = Partial<
    Record<Exclude<UrlFilterKey, 'policy'>, string[]>
> & {
    policy?: PolicyFilter[];
};

export const parsePolicyUrlValue = (value: string): PolicyFilter[] => {
    try {
        return JSON.parse(value);
    } catch {
        return [];
    }
};

export const urlValueParsers: Partial<
    Record<UrlFilterKey, (value: string) => unknown>
> = {
    policy: parsePolicyUrlValue,
};
