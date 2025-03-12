import type { HTMLChakraProps, SystemStyleObject } from '@chakra-ui/react';
import { Tbody } from '@chakra-ui/react';
import has from 'lodash/has';
import * as React from 'react';
import { CellProps, Column, ReducerTableState, Row } from 'react-table';
import { DataTable } from '../..';
import { useDidUpdate } from '../../../../hooks';
import TableRow from './components/TableRow';
import VirtualizedRows from './components/VirtualizedRows';
import { tableBodyStyles } from './styles';

export interface VirtualisationProps {
    tableHeight: number;
    subRowHeight: number;
    rowHeight: number;
    subRowStyles?: SystemStyleObject;
}
interface ResizableBodyProps extends HTMLChakraProps<'div'> {
    getTableBodyProps: any;
    rows: Array<any>;
    prepareRow: any;
    visibleColumns: Array<Column>;
    data: Array<any>;
    renderRowSubComponent?: any;
    onRowChecked?: (row: any) => void;
    onRowClicked?: (row: any) => void;
    checkedRows?: Array<string>;
    keyProp?: string;
    checkAriaLabel?: string;
    hasFixedHeader?: boolean;
    sx?: SystemStyleObject;
    selectedRow?: any; //depending on the content can be diferent things
    virtualisationProps?: VirtualisationProps;
}

export type VirtualizedRow = Row & {
    closeVirtualizedRow: () => void;
};

const ResizableBody: React.FC<React.PropsWithChildren<ResizableBodyProps>> = ({
    getTableBodyProps,
    rows,
    prepareRow,
    visibleColumns,
    data,
    renderRowSubComponent,
    keyProp = 'id',
    onRowChecked,
    onRowClicked,
    checkedRows,
    hasFixedHeader,
    checkAriaLabel = 'Select row for bulk actions',
    sx,
    selectedRow,
    virtualisationProps = null,
    ...rest
}: any) => {
    const handleRowKey = (e: any) => {
        if (e.keyCode === 32 || e.keyCode === 13) {
            const { parentElement } = e.currentTarget;
            if (parentElement) {
                parentElement.click();
            }
        }
    };
    const handleCheckboxKey = ({ keyCode }: any, cell: any) => {
        if (keyCode === 32 || keyCode === 13) {
            onRowChecked(cell.row);
        }
    };

    const handleCheckboxClick = (e: any, cell: any) => {
        onRowChecked(cell.row);
        e.preventDefault();
        e.stopPropagation();
    };

    useDidUpdate(() => {
        const row =
            selectedRow &&
            rows.find((obj: any) => obj.original.id === selectedRow.id);

        // select the row
        if (row && has(row, 'isExpanded') && !row.isExpanded) {
            row.toggleRowExpanded();
        }

        // deselect any previously expanded rows, note: this algo will also
        // detect when selectedRow changes to undefined, and deselect it
        rows.forEach((row: any) => {
            if (row.original.id !== selectedRow?.id && row.isExpanded) {
                row.toggleRowExpanded();
            }
        });
    }, [selectedRow]);

    const getRows = () =>
        rows.map((row: any, index: number) => (
            <TableRow
                row={row}
                prepareRow={prepareRow}
                keyProp={keyProp}
                onRowClicked={onRowClicked}
                visibleColumns={visibleColumns}
                renderRowSubComponent={renderRowSubComponent}
                data={data}
                handleCheckboxClick={handleCheckboxClick}
                handleCheckboxKey={handleCheckboxKey}
                handleRowKey={handleRowKey}
                checkAriaLabel={checkAriaLabel}
                index={index}
                checkedRows={checkedRows}
                hasFixedHeader={hasFixedHeader}
            />
        ));

    return (
        <Tbody
            as='div'
            sx={{ ...tableBodyStyles, ...sx }}
            {...getTableBodyProps}
            {...rest}
        >
            {virtualisationProps ? (
                <VirtualizedRows
                    rows={rows}
                    prepareRow={prepareRow}
                    checkedRows={checkedRows}
                    keyProp={keyProp}
                    onRowClicked={onRowClicked}
                    virtualisationProps={virtualisationProps}
                    hasFixedHeader={hasFixedHeader}
                    handleCheckboxKey={handleCheckboxKey}
                    handleRowKey={handleRowKey}
                    handleCheckboxClick={handleCheckboxClick}
                    checkAriaLabel={checkAriaLabel}
                    visibleColumns={visibleColumns}
                    renderRowSubComponent={renderRowSubComponent}
                    data={data}
                />
            ) : (
                getRows()
            )}
        </Tbody>
    );
};

const REACT_TABLE_EXPANDED = 'toggleRowExpanded';

export const getTableStateReducer = (
    newState: ReducerTableState<object>,
    action: { type: string },
    prevState: ReducerTableState<object>,
) => {
    // intercepts expand toggles and collapses other expanded row(s)
    if (action.type === REACT_TABLE_EXPANDED) {
        const prevTokens = Object.keys(prevState.expanded);
        const newTokens = Object.keys(newState.expanded);

        if (newTokens.length > 1) {
            const nextExpanded: { [key: string]: boolean } = {};

            newTokens.forEach((token) => {
                if (!prevTokens.includes(token)) {
                    nextExpanded[token] = true;
                }
            });

            return { ...newState, expanded: nextExpanded };
        }
    }

    return newState;
};

export const checkedTableColumn = {
    Header: null,
    Cell: null,
    minWidth: 30,
    width: 30,
    maxWidth: 30,
    accessor: 'check',
};

export const EXPANDO_COLUMN_ID = 'table-expando-cell';

export const expandoTableColumn = {
    Header: '',
    Cell: ({ row }: CellProps<any>) => (
        <DataTable.ExpandoCell
            isExpanded={(row as any)?.isExpanded}
            value=''
            iconProps={{
                marginRight: 0,
            }}
        />
    ),
    disableSortBy: true,
    minWidth: 10,
    maxWidth: 10,
    accessor: EXPANDO_COLUMN_ID,
};

export default ResizableBody;
