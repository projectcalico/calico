import React from 'react';
import { Row } from 'react-table';
import {
    VariableSizeListProps,
    VariableSizeList as _VariableSizeList,
} from 'react-window';
import { TableRowProps } from '../TableRow';
import VirtualizedTableRow, {
    VirtualisationProps,
    VirtualizedRowData,
} from '../VirtualizedTableRow';

const getSize = (
    i: number,
    rows: Row[],
    rowHeight: number,
    subRowHeight: number,
) => (rows[i]?.isExpanded ? subRowHeight : rowHeight);

const VariableSizeList = _VariableSizeList as unknown as React.ComponentType<
    VariableSizeListProps & { ref?: React.Ref<_VariableSizeList> }
>;

type VirtualizedRowsProps = Omit<TableRowProps, 'index' | 'row' | 'onClick'> & {
    virtualisationProps: VirtualisationProps;
    rows: Row<any>[];
};

const VirtualizedRows: React.FC<VirtualizedRowsProps> = ({
    virtualisationProps,
    rows,
    keyProp,
    data,
    ...rest
}) => {
    const ref = React.useRef<_VariableSizeList | null>(null);
    const { rowHeight, subRowHeight, shouldAnimate } = virtualisationProps;

    return (
        <VariableSizeList
            ref={ref}
            height={virtualisationProps.tableHeight}
            itemCount={rows.length}
            itemSize={(i) => getSize(i, rows, rowHeight, subRowHeight)}
            width={'full'}
            itemKey={(index, state: VirtualizedRowData) =>
                state.data[index][keyProp]
            }
            itemData={
                {
                    rows,
                    keyProp,
                    virtualisationProps,
                    virtualizationRef: ref,
                    data,
                    shouldAnimate,
                    ...rest,
                } satisfies VirtualizedRowData
            }
        >
            {VirtualizedTableRow}
        </VariableSizeList>
    );
};

export default VirtualizedRows;
