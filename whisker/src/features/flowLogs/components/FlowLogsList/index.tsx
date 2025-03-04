import React from 'react';
import { getTableColumns } from './flowLogsTable';
import FlowLogDetails from '../FlowLogDetails';
import { CellProps } from 'react-table';
import { ApiError, FlowLog } from '@/types/api';
import { headerStyles, subRowStyles, tableStyles } from './styles';
import {
    DataTable,
    TableSkeleton,
} from '@/libs/tigera/ui-components/components/common';

type FlowLogsListProps = {
    flowLogs?: FlowLog[];
    isLoading?: boolean;
    error?: ApiError | null;
    onRowClicked: () => void;
};
//sum of height of table header, tablist, filters, banner and info
const HEADER_HEIGHT = 210;

const FlowLogsList: React.FC<FlowLogsListProps> = ({
    flowLogs,
    isLoading,
    error,
    onRowClicked,
}) => {
    const renderRowSubComponent = React.useCallback(
        ({ row }: CellProps<FlowLog>) => (
            <FlowLogDetails flowLog={row.original} />
        ),
        [],
    );

    if (isLoading) {
        return (
            <TableSkeleton
                noOfLines={20}
                data-testid='flow-logs-loading-skeleton'
            />
        );
    }

    const body = document.body;
    const height =
        Math.max(body.scrollHeight, body.offsetHeight) - HEADER_HEIGHT;

    return (
        <DataTable.Table
            data-testid='flow-logs-table'
            items={flowLogs}
            columnsGenerator={getTableColumns}
            error={!!error}
            errorLabel='Could not display any flow logs at this time'
            emptyTableLabel='Nothing to show yet. Flows will start to appear shortly.'
            noResultsStyles={{
                py: 24,
                '>div': { fontSize: 'sm' },
            }}
            expandRowComponent={renderRowSubComponent}
            onRowClicked={onRowClicked}
            sx={tableStyles}
            headerStyles={headerStyles}
            autoResetExpandedRow={false}
            virtualisationProps={{
                tableHeight: flowLogs?.length ? height : 0,
                subRowHeight: 630,
                rowHeight: 35,
                subRowStyles: subRowStyles,
            }}
        />
    );
};

export default FlowLogsList;
