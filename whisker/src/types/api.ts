import { OmniFilterOption } from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import { OmniFilterParam } from '@/utils/omniFilter';
import { FlowLogAction } from './render';

type Policy = {
    kind: string;
    name: string;
    namespace: string;
    tier: string;
    action: string;
    policy_index: number;
    rule_index: number;
    trigger: null;
};

export type FlowLog = {
    start_time: Date;
    end_time: Date;
    action: FlowLogAction;
    source_name: string;
    source_namespace: string;
    source_labels: string;
    dest_name: string;
    dest_namespace: string;
    dest_labels: string;
    protocol: string;
    dest_port: string;
    reporter: string;
    packets_in: string;
    packets_out: string;
    bytes_in: string;
    bytes_out: string;
    policies: {
        enforced: Policy[];
        pending: Policy[];
    };
};

export type ApiError = {
    data?: any;
    response?: Response;
};

export type QueryPage = {
    items: OmniFilterOption[];
    total: number;
    currentPage?: number;
    nextPage?: number;
};

export type OmniFilterDataQuery = {
    page: number;
    searchOption?: string;
    filterParam: OmniFilterParam;
};

export type OmniFilterDataQueries = Record<
    OmniFilterParam,
    OmniFilterDataQuery | null
>;

export type ApiFilterResponse = {
    items: OmniFilterOption[];
    total: number;
};

export type UseStreamResult<T> = {
    data: T[];
    error: ApiError | null;
    startStream: (path?: string) => void;
    stopStream: () => void;
    isWaiting: boolean;
    isDataStreaming: boolean;
    hasStoppedStreaming: boolean;
};

export type FilterHintsQueryList = { value: string; type: 'exact' | 'fuzzy' };

export type FilterHintsQuery = {
    source_names: FilterHintsQueryList[];
    dest_names: FilterHintsQueryList[];
    source_namespaces: FilterHintsQueryList[];
    dest_namespaces: FilterHintsQueryList[];
    protocols: string[];
    dest_ports: number[];
    actions: ('allow' | 'deny' | 'pass')[];
};

export type FilterHintsListKeys = keyof Omit<
    FilterHintsQuery,
    'actions' | 'dest_ports' | 'protocols'
>;
