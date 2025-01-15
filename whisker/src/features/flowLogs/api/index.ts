import { useQuery } from '@tanstack/react-query';
import api from '@/api';
import {FlowLogList} from '@/types/api';

const getFlowLogs = (queryParams?: Record<string, string>) =>
    api.get<FlowLogList>('flows', {
        queryParams,
    });

export const useFlowLogs = (queryParams?: Record<string, string>) =>
    useQuery({
        queryKey: ['flowLogs', queryParams],
        queryFn: () => getFlowLogs(queryParams),
    });

export const useDeniedFlowLogsCount = () => {
    return useFlowLogsCount({ action: 'deny' });
};

export const useFlowLogsCount = (queryParams?: Record<string, string>) => {
    const { data: count } = useQuery({
        queryKey: ['flowLogsCount'],
        queryFn: () => getFlowLogs(queryParams),
        select: (data) => data.total, // todo: maybe stats api
    });

    return count;
};
