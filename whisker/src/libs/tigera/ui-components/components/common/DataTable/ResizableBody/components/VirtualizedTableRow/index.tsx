import { Box, SystemStyleObject } from '@chakra-ui/react';
import { motion } from 'framer-motion';
import * as React from 'react';
import TableRow, { TableRowProps } from '../TableRow';
import { Row } from 'react-table';
import { VariableSizeList } from 'react-window';

export interface VirtualisationProps {
    tableHeight: number;
    subRowHeight: number;
    rowHeight: number;
    subRowStyles?: SystemStyleObject;
}

export type VirtualizedRowData = Omit<
    TableRowProps,
    'index' | 'row' | 'onClick'
> & {
    rows: Array<any>;
    shouldAnimate: (id: string) => boolean;
    onCompleteAnimation: (id: string) => void;
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
        onCompleteAnimation,
        onRowClicked,
        virtualizationRef,
        virtualisationProps,
        ...rest
    },
}: VirtualizedTableRowProps) => {
    const row = rows[index];
    const animate = shouldAnimate(row.original[keyProp]);
    const delay = index * 0.1 + 0.5;

    React.useEffect(() => {
        return () => {
            if (animate) {
                onCompleteAnimation(row.original[keyProp]);
            }
        };
    }, []);

    return (
        <Box position='relative'>
            <motion.div
                style={{
                    position: 'absolute',
                    width: '100%',
                }}
                initial={
                    animate
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
                onAnimationComplete={() => {
                    if (animate) {
                        onCompleteAnimation(row.original[keyProp]);
                    }
                }}
            >
                <TableRow
                    row={row}
                    keyProp={keyProp}
                    style={style}
                    index={index}
                    onClick={() => {
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
                            console.log('resetting height');
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
