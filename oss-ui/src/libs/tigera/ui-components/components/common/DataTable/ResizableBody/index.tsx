import * as React from 'react';
import { Tr, Tbody, Td, Checkbox } from '@chakra-ui/react';
import { CellProps, ReducerTableState } from 'react-table';
import type { HTMLChakraProps } from '@chakra-ui/react';
import has from 'lodash/has';
import { Column } from 'react-table';
import type { SystemStyleObject } from '@chakra-ui/react';
import { tableBodyStyles, checkboxStyles } from './styles';
import { useDidUpdate } from '../../../../hooks';
import { DataTable } from '../..';

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
}

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

    return (
        <Tbody
            as='div'
            sx={{ ...tableBodyStyles, ...sx }}
            {...getTableBodyProps}
            {...rest}
        >
            {rows.map((row: any, index: number) => {
                prepareRow(row);
                const isRowChecked =
                    checkedRows && checkedRows.includes(row.original[keyProp]);

                return (
                    <React.Fragment key={row.original[keyProp]}>
                        <Tr
                            as='div'
                            key={row.original[keyProp]}
                            data-row-key={row.original[keyProp]}
                            className={row.original?.className}
                            {...row.getRowProps()}
                            onClick={() => {
                                // check the prop is set before executing the callback
                                if (onRowClicked) {
                                    onRowClicked(row);
                                }
                                // toggle the expander
                                return (
                                    has(row, 'isExpanded') &&
                                    row.toggleRowExpanded()
                                );
                            }}
                            data-expanded={row.isExpanded}
                            sx={{
                                _hover: row.isExpanded
                                    ? {
                                          color: 'tigeraBlack',
                                          bg: 'tigeraBlueMedium',
                                      }
                                    : {
                                          color: 'tigeraBlack',
                                          bg: 'tigera-color-table-row-hover',
                                      },
                                cursor: has(row, 'isExpanded')
                                    ? 'pointer'
                                    : 'cursor',
                                bg: row.isExpanded
                                    ? 'tigera-color-table-row-expanded !important'
                                    : isRowChecked
                                      ? 'tigeraBlueLight'
                                      : 'tigera-color-table-row',
                                ...(hasFixedHeader && index === 0
                                    ? {
                                          mt: 8, // this positions first row under fixed header
                                      }
                                    : {}),
                            }}
                        >
                            {row.cells.map((cell: any, i: number) => {
                                const hasCheckboxes = checkedRows !== undefined;
                                const isCheckCell = hasCheckboxes && i === 0;
                                const isFirstExpandoCell =
                                    (hasCheckboxes && i === 1) ||
                                    (!hasCheckboxes && i === 0);

                                return (
                                    <Td
                                        as='div'
                                        data-testid={'cell-body'}
                                        tabIndex={
                                            (hasCheckboxes && i <= 1) ||
                                            (!hasCheckboxes && i === 0)
                                                ? 0
                                                : -1
                                        }
                                        {...cell.getCellProps([
                                            {
                                                style: cell.column?.style,
                                            },
                                        ])}
                                        key={i}
                                        sx={{
                                            ...(row.isExpanded
                                                ? {
                                                      color: 'tigera-color-on-table-row-expanded',
                                                      'button[aria-haspopup="menu"]':
                                                          {
                                                              color: 'tigeraWhite',
                                                              _hover: {
                                                                  color: 'tigeraBlack',
                                                              },
                                                          },
                                                      'button[aria-expanded="true"]':
                                                          {
                                                              color: 'tigeraBlack',
                                                          },
                                                  }
                                                : {
                                                      color: 'tigera-color-on-surface',
                                                  }),
                                            ...(cell.column?.id ===
                                                EXPANDO_COLUMN_ID && {
                                                pr: 0,
                                            }),
                                        }}
                                        {...(isFirstExpandoCell && {
                                            onKeyUp: handleRowKey,
                                        })}
                                        {...(isCheckCell && {
                                            onClick: (e) =>
                                                handleCheckboxClick(e, cell),
                                            onKeyUp: (e) =>
                                                handleCheckboxKey(e, cell),
                                        })}
                                    >
                                        {isCheckCell ? (
                                            <Checkbox
                                                sx={checkboxStyles}
                                                aria-checked={isRowChecked}
                                                tabIndex={-1}
                                                isChecked={isRowChecked}
                                                aria-label={checkAriaLabel}
                                                data-testid={'cell-checkbox'}
                                            />
                                        ) : (
                                            cell.render('Cell')
                                        )}
                                    </Td>
                                );
                            })}
                        </Tr>

                        {row.isExpanded && renderRowSubComponent ? (
                            <Tr as='div'>
                                <Td
                                    as='div'
                                    colSpan={visibleColumns.length}
                                    p={0}
                                >
                                    {renderRowSubComponent({
                                        row,
                                        data,
                                    })}
                                </Td>
                            </Tr>
                        ) : null}
                    </React.Fragment>
                );
            })}
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
