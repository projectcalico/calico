import { objToQueryStr } from '@/libs/tigera/ui-components/utils';
import { FlowLog as ApiFlowLog } from '@/types/api';
import { FlowLog, UniqueFlowLogs } from '@/types/render';
import { v4 as uuid } from 'uuid';

export const transformFlowLogsResponse = ({
    start_time,
    end_time,
    ...rest
}: ApiFlowLog) => ({
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

export const handleDuplicateFlowLogs = (
    unique: UniqueFlowLogs & {
        flowLog: FlowLog;
    },
): UniqueFlowLogs & {
    flowLog: FlowLog | null;
} => {
    const { flowLog, flowLogs, startTime } = unique;
    const { id: _id, ...rest } = flowLog;
    const json = JSON.stringify(rest);

    if (flowLog.start_time.getTime() === startTime) {
        return flowLogs.some((item) => json === item.json)
            ? { startTime, flowLogs: flowLogs, flowLog: null }
            : {
                  startTime,
                  flowLogs: [
                      ...flowLogs,
                      {
                          flowLog,
                          json,
                      },
                  ],
                  flowLog,
              };
    }

    return {
        startTime: flowLog.start_time.getTime(),
        flowLogs: [
            {
                flowLog,
                json,
            },
        ],
        flowLog,
    };
};
