import React from 'react';
import { Column, Row as RowType } from 'react-table';
import Row from '../Row';
import ExpandedRow from '../ExpandedRow';
import { VirtualisationProps } from '../VirtualizedTableRow';

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

    const expandoHeight = React.useRef<number>();

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
                            height: 'max-content',
                        }),
                    }}
                    style={style}
                    {...row.getRowProps({
                        ...style,
                    })}
                    setHeight={(height) => {
                        if (height > 0) {
                            expandoHeight.current = height;
                        }
                        virtualisationProps?.setRowHeight?.(height);
                    }}
                    containerHeight={expandoHeight.current}
                />
            ) : null}
        </React.Fragment>
    );
};

export default TableRow;
