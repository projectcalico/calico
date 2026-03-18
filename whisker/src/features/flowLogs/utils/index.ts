import { objToQueryStr } from '@/libs/tigera/ui-components/utils';
import { FlowLog as ApiFlowLog } from '@/types/api';
import { FlowLog, UniqueFlowLogs } from '@/types/render';
import { v4 as uuid } from 'uuid';
import { VisibleColumns } from '../components/FlowLogsList';
import { ColumnName } from '../components/FlowLogsList/flowLogsTable';

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

export const getV1Columns = (v1StoredColumns: string, storageKey: string) => {
    const v1Columns = v1StoredColumns ? JSON.parse(v1StoredColumns) : [];
    const newColumns: VisibleColumns = {
        start_time: false,
        end_time: false,
        action: false,
        source_namespace: false,
        source_name: false,
        dest_namespace: false,
        dest_name: false,
        protocol: false,
        dest_port: false,
        // default newest column to true
        reporter: true,
    };

    if (v1Columns.length > 0) {
        v1Columns.forEach((columnName: ColumnName) => {
            newColumns[columnName] = true;
        });
    }

    window.localStorage.removeItem('whisker-flow-logs-stream-columns');
    window.localStorage.setItem(storageKey, JSON.stringify(newColumns));

    return newColumns;
};

export const getV2Columns = (
    storedColumns: string,
    key: string,
    initialValue: VisibleColumns,
) => {
    const parsedItem: Record<ColumnName, boolean> = storedColumns
        ? JSON.parse(storedColumns)
        : initialValue;

    // account for new columns in the future
    Object.keys(initialValue).forEach((key) => {
        const columnName = key as ColumnName;

        if (!Object.hasOwn(parsedItem, key)) {
            parsedItem[columnName] = initialValue[columnName];
        }
    });

    // account for removed columns in the future
    Object.keys(parsedItem).forEach((key) => {
        const columnName = key as ColumnName;

        if (!Object.hasOwn(initialValue, key)) {
            delete parsedItem[columnName];
        }
    });

    window.localStorage.setItem(key, JSON.stringify(parsedItem));

    return parsedItem;
};

export const transformStartTime = (startTime: number) => startTime * -60;

export const updateFirstFlowStartTime = (
    data: FlowLog[],
    filterFlowStartTime: number | null,
    setFirstFlowStartTime: (startTime: number | null) => void,
) => {
    if (filterFlowStartTime === null && data.length > 0) {
        const sorted = data.sort(
            (a, b) => b.start_time.getTime() - a.start_time.getTime(),
        );
        setFirstFlowStartTime(sorted[data.length - 1].start_time.getTime());
    }
};
