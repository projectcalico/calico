import { SystemStyleObject, Td, Tr } from '@chakra-ui/react';
import React, { useRef } from 'react';
import { Column, Row as RowType } from 'react-table';

type ExpandedRowProps = {
    visibleColumns: Array<Column>;
    renderRowSubComponent?: any;
    sx?: SystemStyleObject;
    row: RowType<any>;
    data: Array<any>;
    setHeight?: (height: number) => void;
    containerHeight?: number;
};

const ExpandedRow: React.FC<ExpandedRowProps> = ({
    renderRowSubComponent,
    visibleColumns,
    row,
    data,
    sx,
    setHeight,
    containerHeight,
    ...rest
}) => {
    const ref = useRef<any>();

    React.useEffect(() => {
        setHeight?.(ref.current?.getBoundingClientRect().height);
    }, []);

    return (
        <Tr
            as='div'
            sx={sx}
            {...rest}
            {...(setHeight && {
                minHeight: containerHeight,
                backgroundColor: 'tigeraBlack',
            })}
        >
            <Td
                as='div'
                p={0}
                colSpan={visibleColumns.length}
                width={'full'}
                {...(setHeight && {
                    ref,
                    overflowY: 'auto',
                })}
            >
                {renderRowSubComponent({
                    row,
                    data,
                    height: containerHeight,
                })}
            </Td>
        </Tr>
    );
};
export default ExpandedRow;
