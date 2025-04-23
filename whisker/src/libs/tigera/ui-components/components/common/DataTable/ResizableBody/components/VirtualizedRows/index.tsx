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
) => (rows[i]?.isExpanded ? subRowHeight + rowHeight : rowHeight);

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
    const [expandoHeight, setExpandoHeight] = React.useState(0);
    const { rowHeight, shouldAnimate } = virtualisationProps;

    React.useEffect(() => {
        ref.current?.resetAfterIndex(0);
    }, [expandoHeight]);

    return (
        <VariableSizeList
            ref={ref}
            height={virtualisationProps.tableHeight}
            itemCount={rows.length}
            itemSize={(i) => getSize(i, rows, rowHeight, expandoHeight)}
            width={'full'}
            itemKey={(index, state: VirtualizedRowData) =>
                state.data[index][keyProp]
            }
            itemData={
                {
                    rows,
                    keyProp,
                    virtualisationProps: {
                        ...virtualisationProps,
                        setRowHeight: (height) => setExpandoHeight(height),
                    },
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
