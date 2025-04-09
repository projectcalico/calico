import { FlowLog as ApiFlowLog } from './api';

export type FlowLogAction = 'Allow' | 'Deny' | 'Pass' | 'Log';

export type FlowLog = Omit<ApiFlowLog, 'start_time' | 'end_time'> & {
    id: string;
    start_time: Date;
    end_time: Date;
};

export type AppConfig = {
    config: {
        cluster_id: string;
        cluster_type: string;
        calico_version: string;
        notifications: 'Enabled' | 'Disabled';
    };
};
