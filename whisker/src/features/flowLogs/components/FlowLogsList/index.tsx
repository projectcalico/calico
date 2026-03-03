import {
    DataTable,
    TableSkeleton,
} from '@/libs/tigera/ui-components/components/common';
import { VirtualizedRow } from '@/libs/tigera/ui-components/components/common/DataTable';
import ReorderableCheckList from '@/libs/tigera/ui-components/components/common/ReorderableCheckList';
import { ApiError } from '@/types/api';
import { FlowLog } from '@/types/render';
import React from 'react';
import { CellProps } from 'react-table';
import { useShouldAnimate, useStoredColumns } from '../../hooks';
import FlowLogDetails from '../FlowLogDetails';
import {
    ColumnName,
    getStandardColumns,
    getTableColumns,
} from './flowLogsTable';
import { headerStyles, subRowStyles, tableStyles } from './styles';

type FlowLogsListProps = {
    flowLogs: FlowLog[];
    isLoading?: boolean;
    error?: ApiError | null;
    onRowClicked: (row: VirtualizedRow) => void;
    onSortClicked: () => void;
    maxStartTime: number;
    heightOffset: number;
    totalItems: number;
};

const columnsHeight = 36;

export type VisibleColumns = Record<ColumnName, boolean>;

const defaultColumns: VisibleColumns = {
    start_time: true,
    end_time: true,
    action: true,
    source_namespace: true,
    source_name: true,
    dest_namespace: true,
    dest_name: true,
    protocol: true,
    dest_port: true,
    reporter: true,
};

const FlowLogsList: React.FC<FlowLogsListProps> = ({
    flowLogs,
    isLoading,
    error,
    onRowClicked,
    onSortClicked,
    maxStartTime,
    heightOffset,
    totalItems,
}) => {
    const handleOpenColumnCustomizer = React.useCallback(() => {
        setIsColumnCustomizerOpen(true);
    }, []);

    const [storedColumns, setStoredColumns] = useStoredColumns(defaultColumns);

    const columnOrder = Object.keys(storedColumns);
    const reorderableColumns = getStandardColumns().sort(
        (a, b) =>
            columnOrder.indexOf(a.Header as string) -
            columnOrder.indexOf(b.Header as string),
    );
    const tableColumns = getTableColumns(
        handleOpenColumnCustomizer,
        reorderableColumns,
    );

    const memoizedTableColumns = React.useMemo(
        () =>
            tableColumns.filter(
                (column) =>
                    column.disableReordering ||
                    storedColumns[column.accessor as ColumnName],
            ),
        [storedColumns],
    );

    const [isColumnCustomizerOpen, setIsColumnCustomizerOpen] =
        React.useState(false);
    const shouldAnimate = useShouldAnimate(maxStartTime, totalItems);

    const renderRowSubComponent = React.useCallback(
        ({ row, height }: CellProps<FlowLog>) => (
            <FlowLogDetails flowLog={row.original} height={height} />
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
        Math.max(body.scrollHeight, body.offsetHeight) -
        (columnsHeight + heightOffset);

    return (
        <>
            {isColumnCustomizerOpen && (
                <ReorderableCheckList
                    size='sm'
                    title='Customize Columns'
                    items={Object.entries(storedColumns).map(
                        ([key, value]) => ({
                            Header: key,
                            checked: value,
                        }),
                    )}
                    onSave={(reorderedColumns) => {
                        setStoredColumns(
                            reorderedColumns.reduce(
                                (acc, column) => ({
                                    ...acc,
                                    [column.Header as ColumnName]:
                                        column.checked,
                                }),
                                {} as Record<ColumnName, boolean>,
                            ),
                        );
                    }}
                    keyProp='Header'
                    labelProp='Header'
                    isOpen={isColumnCustomizerOpen}
                    onClose={() => setIsColumnCustomizerOpen(false)}
                />
            )}
            <DataTable.Table
                data-testid='flow-logs-table'
                items={flowLogs}
                columnsGenerator={() => []}
                memoizedColumnsGenerator={memoizedTableColumns}
                error={!!error}
                errorLabel='Could not display any flow logs at this time'
                emptyTableLabel='Nothing to show yet. Flows will start to appear shortly.'
                noResultsStyles={{
                    py: 24,
                    '>div': { fontSize: 'sm' },
                    borderBottom: 'none',
                }}
                expandRowComponent={renderRowSubComponent}
                onRowClicked={(row) => onRowClicked(row)}
                sx={tableStyles}
                headerStyles={headerStyles}
                autoResetExpandedRow={true}
                virtualisationProps={{
                    tableHeight: flowLogs?.length ? height : 0,
                    rowHeight: 35,
                    subRowStyles: subRowStyles,
                    shouldAnimate,
                }}
                onSortClicked={onSortClicked}
                keyProp='id'
                initialState={{
                    sortBy: [{ id: 'start_time', desc: true }],
                }}
                size='lg'
            />
        </>
    );
};

export default FlowLogsList;
