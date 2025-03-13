import { FlowLog as ApiFlowLog } from './api';

export type FlowLogAction = 'Allow' | 'Deny' | 'Pass' | 'Log';

export type FlowLog = ApiFlowLog & {
    id?: string;
};
