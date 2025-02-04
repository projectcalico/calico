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
