export const tableLevelDataFilterIds = [
    'source_namespace',
    'source_name',
    'dest_namespace',
    'dest_name',
] as const;

export const tableLevelFilterIds = [
    'policy',
    ...tableLevelDataFilterIds,
    'reporter',
    'dest_port',
    'action',
    'start_time',
] as const;

export type TableLevelFilterId = (typeof tableLevelFilterIds)[number];

export const filterLabels: Record<TableLevelFilterId, string> = {
    policy: 'Policy',
    source_namespace: 'Source Namespace',
    source_name: 'Source',
    dest_namespace: 'Dest Namespace',
    dest_name: 'Destination',
    reporter: 'Reporter',
    dest_port: 'Port',
    action: 'Action',
    start_time: 'Start Time',
};
