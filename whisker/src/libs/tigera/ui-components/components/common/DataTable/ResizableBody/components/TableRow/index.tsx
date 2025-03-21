import React from 'react';
import { Column, Row as RowType } from 'react-table';
import { VirtualisationProps } from '../..';
import Row from '../Row';
import ExpandedRow from '../ExpandedRow';

export type TableRowProps = {
    index: number;
    row: RowType<any>;
    prepareRow: any;
    checkedRows?: Array<string>;
    keyProp: string;
    onRowClicked?: (row: any) => void;
    virtualisationProps?: VirtualisationProps;
    hasFixedHeader?: boolean;
    handleCheckboxClick: (e: any, cell: any) => void;
    checkAriaLabel?: string;
    visibleColumns: Array<Column>;
    data: Array<any>;
    renderRowSubComponent?: any;
    handleRowKey: (e: any) => void;
    handleCheckboxKey: ({ keyCode }: any, cell: any) => void;
    onClick?: (row: RowType) => void;
    style?: any;
};

export const TableRow: React.FC<TableRowProps> = ({
    row,
    prepareRow,
    keyProp,
    onRowClicked,
    visibleColumns,
    renderRowSubComponent,
    data,
    style = {},
    handleCheckboxClick,
    handleCheckboxKey,
    handleRowKey,
    checkAriaLabel,
    index,
    checkedRows,
    hasFixedHeader,
    virtualisationProps,
    onClick,
}) => {
    prepareRow(row);

    const handleClick = () => {
        if (onRowClicked) {
            onRowClicked(row);
        }
    };

    return (
        <React.Fragment key={row.original[keyProp]}>
            <Row
                handleCheckboxClick={handleCheckboxClick}
                handleCheckboxKey={handleCheckboxKey}
                handleRowKey={handleRowKey}
                index={index}
                checkAriaLabel={checkAriaLabel}
                checkedRows={checkedRows}
                hasFixedHeader={hasFixedHeader}
                row={row}
                keyProp={keyProp}
                style={style}
                onClick={onClick ?? handleClick}
            />

            {row.isExpanded && renderRowSubComponent ? (
                <ExpandedRow
                    visibleColumns={visibleColumns}
                    renderRowSubComponent={renderRowSubComponent}
                    row={row}
                    data={data}
                    sx={{
                        ...(virtualisationProps && {
                            ...style,
                            ...virtualisationProps.subRowStyles,
                            top: style?.top + virtualisationProps.rowHeight,
                        }),
                    }}
                    style={style}
                    {...row.getRowProps({
                        ...style,
                    })}
                />
            ) : null}
        </React.Fragment>
    );
};

export default TableRow;
