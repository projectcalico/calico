import { CellProps } from 'react-table';
import { DataTable } from '@/libs/tigera/ui-components/components/common';
import { FlowLog } from '@/types/api';
import FlowLogActionIndicator from '@/components/common/FlowLogActionIndicator';
import { AddIcon } from '@chakra-ui/icons';
import { Button, Icon } from '@chakra-ui/react';

export const getTableColumns = (onColumnCustomizerOpen: () => void) => [
    { ...DataTable.expandoTableColumn, disableReordering: true, checked: true },
    {
        Header: 'start_time',
        width: 40,
        minWidth: 20,
        accessor: 'start_time',
        Cell: ({ row }: CellProps<FlowLog>) => {
            const { start_time } = row.original;

            return new Date(start_time).toLocaleTimeString();
        },
        checked: true,
    },
    {
        Header: 'end_time',
        width: 40,
        minWidth: 20,
        accessor: 'end_time',
        Cell: ({ row }: CellProps<FlowLog>) => {
            const { end_time } = row.original;

            return new Date(end_time).toLocaleTimeString();
        },
        checked: true,
    },
    {
        Header: 'action',
        width: 40,
        minWidth: 25,
        accessor: 'action',
        Cell: ({ row }: CellProps<FlowLog>) => {
            const { action } = row.original;

            return <FlowLogActionIndicator action={action} />;
        },
        checked: true,
    },
    {
        Header: 'source_name',
        width: 100,
        minWidth: 50,
        accessor: 'source_name',
        checked: true,
    },
    {
        Header: 'source_namespace',
        width: 70,
        minWidth: 30,
        accessor: 'source_namespace',
        checked: true,
    },
    {
        Header: 'dest_name',
        width: 100,
        minWidth: 50,
        accessor: 'dest_name',
        checked: true,
    },
    {
        Header: 'dest_namespace',
        width: 70,
        minWidth: 30,
        accessor: 'dest_namespace',
        checked: true,
    },
    {
        Header: 'protocol',
        width: 40,
        minWidth: 20,
        accessor: 'protocol',
        checked: true,
    },
    {
        Header: 'dest_port',
        width: 40,
        minWidth: 20,
        accessor: 'dest_port',
        checked: true,
    },
    {
        Header: (
            <Button
                variant={'solid'}
                borderRadius={0}
                mr='0'
                onClick={() => {
                    onColumnCustomizerOpen();
                }}
            >
                <Icon as={AddIcon} />
            </Button>
        ),
        disableSortBy: true,
        maxWidth: 45,
        accessor: 'customizer_header',
        disableResizing: true,
        disableReordering: true,
        checked: true,
    },
];
