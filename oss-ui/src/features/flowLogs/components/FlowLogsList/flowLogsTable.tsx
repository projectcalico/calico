import { CellProps } from 'react-table';
import { DataTable } from '@/libs/tigera/ui-components/components/common';
import { FlowLog } from '@/types/api';
import FlowLogActionIndicator from '@/components/common/FlowLogActionIndicator';

export const getTableColumns = () => [
    DataTable.expandoTableColumn,
    {
        Header: 'start_time',
        width: 40,
        minWidth: 20,
        accessor: 'start_time',
        Cell: ({ row }: CellProps<FlowLog>) => {
            const { start_time } = row.original;

            return new Date(start_time).toLocaleTimeString();
        },
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
    },
    {
        Header: 'source_name',
        width: 100,
        minWidth: 50,
        accessor: 'source_name',
    },
    {
        Header: 'source_namespace',
        width: 70,
        minWidth: 30,
        accessor: 'source_namespace',
    },
    {
        Header: 'dest_name',
        width: 100,
        minWidth: 50,
        accessor: 'dest_name',
    },
    {
        Header: 'dest_namespace',
        width: 70,
        minWidth: 30,
        accessor: 'dest_namespace',
    },
    {
        Header: 'protocol',
        width: 40,
        minWidth: 20,
        accessor: 'protocol',
    },
    {
        Header: 'dest_port',
        width: 40,
        minWidth: 20,
        accessor: 'dest_port',
    },
];
