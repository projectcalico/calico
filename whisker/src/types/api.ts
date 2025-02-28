import { OmniFilterOption } from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import { OmniFilterParam } from '@/utils/omniFilter';

export type FlowLog = {
    start_time: Date;
    end_time: Date;
    action: 'allow' | 'deny' | 'pass' | 'log';
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
