import { Checkbox, Td, Tr } from '@chakra-ui/react';
import has from 'lodash/has';
import React from 'react';
import { Row as RowType } from 'react-table';
import { EXPANDO_COLUMN_ID } from '../..';
import { checkboxStyles } from '../../styles';

type RowProps = {
    index: number;
    row: RowType<any>;
    keyProp: string;
    checkedRows?: Array<string>;
    hasFixedHeader?: boolean;
    handleCheckboxClick: (e: any, cell: any) => void;
    checkAriaLabel?: string;
    handleRowKey: (e: any) => void;
    handleCheckboxKey: ({ keyCode }: any, cell: any) => void;
    style?: any;
    onClick?: (row: RowType) => void;
};

export const Row: React.FC<RowProps> = ({
    index,
    row,
    keyProp,
    checkedRows,
    hasFixedHeader,
    handleCheckboxClick,
    checkAriaLabel,
    handleRowKey,
    handleCheckboxKey,
    style = {},
    onClick,
}) => {
    const isRowChecked =
        checkedRows && checkedRows.includes(row.original[keyProp]);
    return (
        <Tr
            as='div'
            data-row-key={row.original[keyProp]}
            className={row.original?.className}
            {...row.getRowProps({ style })}
            onClick={() => {
                if (onClick) {
                    onClick({
                        ...row,
                        isExpanded: !row.isExpanded,
                    });
                }
                // toggle the expander
                return has(row, 'isExpanded') && row.toggleRowExpanded();
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
                cursor: has(row, 'isExpanded') ? 'pointer' : 'cursor',
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
                    (hasCheckboxes && i === 1) || (!hasCheckboxes && i === 0);

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
                                      'button[aria-haspopup="menu"]': {
                                          color: 'tigeraWhite',
                                          _hover: {
                                              color: 'tigeraBlack',
                                          },
                                      },
                                      'button[aria-expanded="true"]': {
                                          color: 'tigeraBlack',
                                      },
                                  }
                                : {
                                      color: 'tigera-color-on-surface',
                                  }),
                            ...(cell.column?.id === EXPANDO_COLUMN_ID && {
                                pr: 0,
                            }),
                        }}
                        {...(isFirstExpandoCell && {
                            onKeyUp: handleRowKey,
                        })}
                        {...(isCheckCell && {
                            onClick: (e) => handleCheckboxClick(e, cell),
                            onKeyUp: (e) => handleCheckboxKey(e, cell),
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
    );
};

export default Row;
