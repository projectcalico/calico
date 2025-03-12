import { VirtualizedRow } from '@/libs/tigera/ui-components/components/common/DataTable';
import { ApiError, FlowLog } from '@/types/api';
import React from 'react';
import { useOutletContext } from 'react-router-dom';
import FlowLogsList from '../FlowLogsList';

export type FlowLogsContext = {
    view: 'all' | 'denied';
    flowLogs: FlowLog[];
    error: ApiError | null;
    onRowClicked: (row: VirtualizedRow) => void;
    onSortClicked: () => void;
};

const FlowLogsContainer: React.FC = () => {
    const { flowLogs, error, onRowClicked, onSortClicked } =
        useOutletContext<FlowLogsContext>();

    return (
        <FlowLogsList
            flowLogs={flowLogs}
            isLoading={false}
            error={error}
            onRowClicked={onRowClicked}
            onSortClicked={onSortClicked}
        />
    );
};

export default FlowLogsContainer;
