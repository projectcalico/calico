import React from 'react';
import { getTableColumns } from './flowLogsTable';
import FlowLogDetails from '../FlowLogDetails';
import { CellProps } from 'react-table';
import { ApiError, FlowLog } from '@/types/api';
import { headerStyles, tableStyles } from './styles';
import {
    DataTable,
    TableSkeleton,
} from '@/libs/tigera/ui-components/components/common';

type FlowLogsListProps = {
    flowLogs?: FlowLog[];
    isLoading?: boolean;
    error?: ApiError | null;
};

const FlowLogsList: React.FC<FlowLogsListProps> = ({
    flowLogs,
    isLoading,
    error,
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

    return (
        <DataTable.Table
            data-testid='flow-logs-table'
            items={flowLogs}
            columnsGenerator={getTableColumns}
            keyProp='source_name'
            error={!!error}
            errorLabel='Could not display any flow logs at this time'
            emptyTableLabel='Nothing to show yet'
            noResultsStyles={{ py: 24 }}
            expandRowComponent={renderRowSubComponent}
            sx={tableStyles}
            headerStyles={headerStyles}
        />
    );
};

export default FlowLogsList;
