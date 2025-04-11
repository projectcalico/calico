import { Box, SystemStyleObject } from '@chakra-ui/react';
import { motion } from 'framer-motion';
import * as React from 'react';
import TableRow, { TableRowProps } from '../TableRow';
import { Row } from 'react-table';
import { VariableSizeList } from 'react-window';

export interface VirtualisationProps {
    tableHeight: number;
    rowHeight: number;
    subRowStyles?: SystemStyleObject;
    shouldAnimate: (obj: any) => boolean;
    setRowHeight?: (height: number) => void;
}

export type VirtualizedRowData = Omit<
    TableRowProps,
    'index' | 'row' | 'onClick'
> & {
    rows: Array<any>;
    shouldAnimate: (obj: any) => boolean;
    virtualizationRef: React.MutableRefObject<VariableSizeList<any> | null>;
};

type VirtualizedTableRowProps = {
    index: number;
    style?: React.CSSProperties;
    data: VirtualizedRowData;
};

const VirtualizedTableRow = ({
    index,
    style,
    data: {
        rows,
        shouldAnimate,
        keyProp,
        onRowClicked,
        virtualizationRef,
        virtualisationProps,
        ...rest
    },
}: VirtualizedTableRowProps) => {
    const row = rows[index];
    const animate = React.useRef(shouldAnimate(row.original));
    const delay = index * 0.1 + 0.5;

    return (
        <Box position='relative' overflowX='clip'>
            <motion.div
                style={{
                    position: 'absolute',
                    width: '100%',
                    overflowX: 'clip',
                }}
                initial={
                    animate.current
                        ? {
                              opacity: 0,
                              right: '-200px',
                          }
                        : { opacity: 1, scale: 1, right: 0 }
                }
                animate={{
                    opacity: 1,
                    right: 0,
                }}
                transition={{
                    duration: 0.3,
                    delay,
                    opacity: {
                        duration: 0.8,
                        delay,
                    },
                }}
            >
                <TableRow
                    row={row}
                    keyProp={keyProp}
                    style={style}
                    index={index}
                    onClick={(row) => {
                        if (onRowClicked) {
                            onRowClicked({
                                ...row,
                                closeVirtualizedRow: () => {
                                    if ((row as Row).isExpanded) {
                                        (row as Row).toggleRowExpanded();
                                        virtualizationRef.current?.resetAfterIndex(
                                            0,
                                        );
                                    }
                                },
                            });
                        }

                        if (virtualisationProps) {
                            //force re-calculating the row height
                            virtualizationRef.current?.resetAfterIndex(0);
                        }
                    }}
                    virtualisationProps={virtualisationProps}
                    {...rest}
                />
            </motion.div>
        </Box>
    );
};

export default VirtualizedTableRow;
