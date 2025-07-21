import React from 'react';
import { getTableColumns } from './flowLogsTable';
import FlowLogDetails from '../FlowLogDetails';
import { CellProps, Column } from 'react-table';
import { ApiError } from '@/types/api';
import { FlowLog } from '@/types/render';
import { headerStyles, subRowStyles, tableStyles } from './styles';
import {
    DataTable,
    TableSkeleton,
} from '@/libs/tigera/ui-components/components/common';
import { VirtualizedRow } from '@/libs/tigera/ui-components/components/common/DataTable';
import ReorderableCheckList, {
    ReorderableList,
} from '@/libs/tigera/ui-components/components/common/ReorderableCheckList';
import { useShouldAnimate } from '../../hooks';
import { useLocalStorage } from '@/libs/tigera/ui-components/hooks';

export type CustomColumn = Column & {
    disableReordering?: boolean;
};

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

const defaultColumnNames = getTableColumns(() => undefined)
    .filter((column) => !column.disableReordering)
    .map((column) => column.Header as string);

const expandoIndex = 0;

const getVisibleColumns = (columns: CustomColumn[], storedColumns: string[]) =>
    [
        columns[expandoIndex],
        ...columns
            .slice(1, columns.length - 1)
            .map((column) => ({
                ...column,
                checked:
                    column.disableReordering ??
                    storedColumns.includes(column.Header as string),
            }))
            .sort(
                (a, b) =>
                    storedColumns.indexOf(a.Header as string) -
                    storedColumns.indexOf(b.Header as string),
            ),
        columns[columns.length - 1],
    ] as ReorderableList<CustomColumn>[];

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
    const onColumnCustomizerOpen = () => {
        setColCustomizerVisible(true);
    };

    const originalColumns = getTableColumns(
        onColumnCustomizerOpen,
    ) as ReorderableList<CustomColumn>[];

    const [storedColumns, setStoredColumns] = useLocalStorage(
        'whisker-flow-logs-stream-columns',
        defaultColumnNames,
    );

    const [columns, setColumns] = React.useState<
        ReorderableList<CustomColumn>[]
    >(getVisibleColumns(originalColumns, storedColumns));
    const [colCustomizerVisible, setColCustomizerVisible] =
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

    const customizerIndex = originalColumns.findIndex(
        (col) => col.accessor === 'customizer_header',
    );

    return (
        <>
            {colCustomizerVisible && (
                <ReorderableCheckList
                    size='sm'
                    title='Customize Columns'
                    items={columns.filter((c) => !c.disableReordering)}
                    onSave={(list) => {
                        const newStoredColumns = list
                            .filter((column) => column.checked)
                            .map((column) => column.Header as string);
                        setStoredColumns(newStoredColumns);
                        setColumns([
                            originalColumns[expandoIndex],
                            ...list,
                            originalColumns[customizerIndex],
                        ]);
                    }}
                    keyProp='Header'
                    labelProp='Header'
                    isOpen={colCustomizerVisible}
                    onClose={() => setColCustomizerVisible(false)}
                />
            )}
            <DataTable.Table
                data-testid='flow-logs-table'
                items={flowLogs}
                columnsGenerator={() => []}
                memoizedColumnsGenerator={columns.filter((c) => c.checked)}
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
