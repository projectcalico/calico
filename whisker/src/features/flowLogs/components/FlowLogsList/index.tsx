import React from 'react';
import { getTableColumns } from './flowLogsTable';
import FlowLogDetails from '../FlowLogDetails';
import { CellProps, Column } from 'react-table';
import { ApiError, FlowLog } from '@/types/api';
import { headerStyles, subRowStyles, tableStyles } from './styles';
import {
    DataTable,
    TableSkeleton,
} from '@/libs/tigera/ui-components/components/common';
import { VirtualizedRow } from '@/libs/tigera/ui-components/components/common/DataTable';
import ReorderableCheckList, {
    ReorderableList,
} from '@/libs/tigera/ui-components/components/common/ReorderableCheckList';

export type CustomColumn = Column & {
    disableReordering?: boolean;
};

type FlowLogsListProps = {
    flowLogs?: FlowLog[];
    isLoading?: boolean;
    error?: ApiError | null;
    onRowClicked: (row: VirtualizedRow) => void;
    onSortClicked: () => void;
};
//sum of height of table header, tablist, filters, banner and info
const bannerHeight = 36;
const headerHeight = 54;
const containerPadding = 4;
const omniFiltersHeight = 46;
const tabsHeight = 34;
const columnsHeight = 32;
const HEADER_HEIGHT =
    bannerHeight +
    headerHeight +
    containerPadding +
    omniFiltersHeight +
    tabsHeight +
    columnsHeight;

const FlowLogsList: React.FC<FlowLogsListProps> = ({
    flowLogs,
    isLoading,
    error,
    onRowClicked,
    onSortClicked,
}) => {
    const onColumnCustomizerOpen = () => {
        setColCustomizerVisible(true);
    };

    const originalColumns = getTableColumns(
        onColumnCustomizerOpen,
    ) as ReorderableList<CustomColumn>[];

    const [columns, setColumns] =
        React.useState<ReorderableList<CustomColumn>[]>(originalColumns);
    const [colCustomizerVisible, setColCustomizerVisible] =
        React.useState(false);

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

    const expandoIndex = 0;
    const customizerIndex = originalColumns.findIndex(
        (col) => col.accessor === 'customizer_header',
    );

    return (
        <>
            <ReorderableCheckList
                title='Customize Columns'
                items={columns.filter((c) => !c.disableReordering)}
                onSave={(list) => {
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
                }}
                expandRowComponent={renderRowSubComponent}
                onRowClicked={(row) => onRowClicked(row)}
                sx={tableStyles}
                headerStyles={headerStyles}
                autoResetExpandedRow={true}
                virtualisationProps={{
                    tableHeight: flowLogs?.length ? height : 0,
                    subRowHeight: 700,
                    rowHeight: 35,
                    subRowStyles: subRowStyles,
                }}
                onSortClicked={onSortClicked}
                keyProp='id'
            />
        </>
    );
};

export default FlowLogsList;
