import * as React from 'react';
import * as Chakra from '@chakra-ui/react';
import {
    useTable,
    useResizeColumns,
    useFlexLayout,
    useSortBy,
    Column,
    useExpanded,
} from 'react-table';
import NoResults from '../NoResults';
import ResizableBody from '../ResizableBody';
import ResizableHeader from '../ResizableHeader';
import { getTableStateReducer } from '../ResizableBody/index';
import { SystemStyleObject } from '@chakra-ui/react';
import { has } from 'lodash';

export type ColumnSortEvent = {
    id: string;
    toggleSortBy: () => void;
    isSorted: boolean;
    isSortedDesc: boolean;
    disableSortBy: boolean;
};

export type TableSort = {
    id: string;
    desc: boolean;
};
export type TableState = Partial<{ sortBy: TableSort[] }>;

const DEFAULT_PAGE_SIZE = 25;

export interface TableProps {
    items?: Array<any>;
    isFetching?: boolean;
    hasFixedHeader?: boolean;
    error?: string | boolean;
    errorLabel: string;
    emptyTableLabel: string;
    columnsGenerator: any;
    expandRowComponent?: any;
    onRowClicked?: (row: any) => void;
    expandAll?: any;
    keyProp?: string;
    autoResetExpandedRow?: boolean;
    variant?: string;
    size?: string;
    sx?: SystemStyleObject;
    headerStyles?: SystemStyleObject;
    noResultsStyles?: SystemStyleObject;
    enableResize?: boolean;
    page?: number;
    pageSize?: number;
    isPaginated?: boolean;
    selectedRow?: any; //depending on the content can be different things
    onRowChecked?: (row: any) => void;
    checkedRows?: Array<string>;
    isAllChecked?: boolean;
    onAllChecked?: () => void;
    memoizedColumnsGenerator?: any;
    isSelectable?: boolean;
    onSort?: (column: ColumnSortEvent) => void;
    initialState?: TableState;
}

const Table: React.FC<React.PropsWithChildren<TableProps>> = ({
    items,
    isFetching,
    hasFixedHeader,
    error,
    expandAll = false,
    onRowClicked,
    errorLabel,
    emptyTableLabel,
    columnsGenerator,
    expandRowComponent,
    autoResetExpandedRow,
    keyProp,
    variant,
    size,
    headerStyles,
    enableResize = true,
    page = 0,
    pageSize = DEFAULT_PAGE_SIZE,
    isPaginated = false,
    selectedRow = undefined,
    onRowChecked,
    checkedRows,
    isAllChecked,
    onAllChecked,
    memoizedColumnsGenerator,
    noResultsStyles,
    isSelectable,
    onSort,
    initialState,
    ...rest
}) => {
    const hasItems = items && items.length > 0;
    const reactTableData = () => (hasItems ? items : []);
    const memoizedData = React.useMemo(() => reactTableData(), [items]);
    const defaultMemoizedColumns = React.useMemo<Column[]>(
        () => columnsGenerator(),
        [],
    );
    const memoizedColumns = memoizedColumnsGenerator ?? defaultMemoizedColumns;

    const stateReducer = React.useCallback(
        getTableStateReducer,
        [],
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ) as any;

    const args = [useSortBy, useFlexLayout];

    if (expandRowComponent || isSelectable) {
        args.push(useExpanded as any);
    }

    if (enableResize) {
        args.push(useResizeColumns as any);
    }

    const {
        getTableProps,
        getTableBodyProps,
        headerGroups,
        rows,
        visibleColumns,
        prepareRow,
        toggleAllRowsExpanded,
    } = useTable(
        {
            data: memoizedData as any,
            columns: memoizedColumns as any,
            autoResetSortBy: false,
            autoResetExpanded: autoResetExpandedRow as boolean,
            stateReducer,
            initialState,
        } as any,
        ...args,
    );

    //if page is defined paginates rows allowing the native filtering of the table to work unimpeded
    const visibleRows = isPaginated
        ? rows.slice(page * pageSize, pageSize + page * pageSize)
        : rows;

    React.useEffect(() => {
        if (expandRowComponent) {
            toggleAllRowsExpanded(expandAll);
        }
    }, [expandAll]);

    //close expanded rows when navigating to other pages if in mem-pagination
    React.useEffect(() => {
        if (toggleAllRowsExpanded) {
            toggleAllRowsExpanded(false);
        }
    }, [page]);

    // note: selectedRow logic is not passed to ResizableBody...
    // ResizableBody can be used independantly of Table (and has its own dedicated selectedRow handling for this purpose)
    React.useEffect(() => {
        const row =
            selectedRow &&
            visibleRows.find(
                (obj) => (obj.original as any).id === selectedRow.id,
            );

        // select the row
        if (row && has(row, 'isExpanded') && !row.isExpanded) {
            row.toggleRowExpanded();
        }

        // deselect any previously expanded rows, note: this algo will also
        // detect when selectedRow changes to undefined, and deselect it
        visibleRows.forEach((row: any) => {
            if (row.original.id !== selectedRow?.id && row.isExpanded) {
                row.toggleRowExpanded();
            }
        });
    }, [selectedRow]);

    return (
        <Chakra.Table
            as='div'
            {...getTableProps()}
            variant={variant}
            size={size}
        >
            <ResizableHeader
                enableResize={enableResize}
                headerGroups={headerGroups}
                isFixed={hasFixedHeader}
                sx={headerStyles}
                checkedRows={checkedRows}
                isAllChecked={isAllChecked}
                onAllChecked={onAllChecked}
                onSortCustomHandler={onSort}
            />

            {items && !isFetching && (
                <ResizableBody
                    rows={visibleRows}
                    getTableBodyProps={getTableBodyProps()}
                    data={memoizedData as any}
                    prepareRow={prepareRow}
                    onRowClicked={onRowClicked}
                    visibleColumns={visibleColumns}
                    renderRowSubComponent={expandRowComponent}
                    hasFixedHeader={hasFixedHeader}
                    keyProp={keyProp}
                    data-testid='roles-list-table-body'
                    onRowChecked={onRowChecked}
                    checkedRows={checkedRows}
                    {...rest}
                />
            )}

            {!hasItems && !isFetching && (
                <NoResults
                    colSpan={0}
                    message={error ? errorLabel : emptyTableLabel}
                    sx={noResultsStyles}
                />
            )}
        </Chakra.Table>
    );
};

export default Table;
