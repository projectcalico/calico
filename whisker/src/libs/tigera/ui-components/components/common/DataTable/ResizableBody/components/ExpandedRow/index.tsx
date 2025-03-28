import { SystemStyleObject, Td, Tr } from '@chakra-ui/react';
import React from 'react';
import { Column, Row as RowType } from 'react-table';

type ExpandedRowProps = {
    visibleColumns: Array<Column>;
    renderRowSubComponent?: any;
    sx?: SystemStyleObject;
    row: RowType<any>;
    data: Array<any>;
};

const ExpandedRow: React.FC<ExpandedRowProps> = ({
    renderRowSubComponent,
    visibleColumns,
    row,
    data,
    sx,
    ...rest
}) => (
    <Tr as='div' sx={sx} {...rest}>
        <Td as='div' p={0} colSpan={visibleColumns.length} width={'full'}>
            {renderRowSubComponent({
                row,
                data,
            })}
        </Td>
    </Tr>
);

export default ExpandedRow;
