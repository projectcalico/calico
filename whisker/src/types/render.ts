import { FlowLog as ApiFlowLog } from './api';

export type FlowLogAction = 'Allow' | 'Deny' | 'Pass' | 'Log';

export type FlowLog = Omit<ApiFlowLog, 'start_time' | 'end_time'> & {
    id: string;
    start_time: Date;
    end_time: Date;
};
