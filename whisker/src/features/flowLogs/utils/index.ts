import { objToQueryStr } from '@/libs/tigera/ui-components/utils';
import { FlowLog } from '@/types/api';
import { v4 as uuid } from 'uuid';

export const transformFlowLogsResponse = ({
    start_time,
    end_time,
    ...rest
}: FlowLog) => ({
    ...rest,
    id: uuid(),
    start_time: new Date(start_time),
    end_time: new Date(end_time),
});

export const buildStreamPath = (
    startTimeGte: number | undefined,
    filters: string,
) => {
    const queryString = objToQueryStr({
        watch: true,
        filters,
        startTimeGte,
    });

    return `flows${queryString}`;
};

export const getTimeInSeconds = (time: number | null) =>
    Math.round((time ?? 0) / 1000) || undefined;

export const getSeconds = (date: Date | null) => (date?.getTime() ?? 0) / 1000;
