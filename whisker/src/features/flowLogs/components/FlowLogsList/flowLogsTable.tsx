import { CellProps, Row } from 'react-table';
import { DataTable } from '@/libs/tigera/ui-components/components/common';
import { FlowLog, ReporterLabels } from '@/types/render';
import FlowLogActionIndicator from '@/components/common/FlowLogActionIndicator';
import { AddIcon } from '@chakra-ui/icons';
import { Button, Icon, Tooltip } from '@chakra-ui/react';

enum Columns {
    startTime = 'start_time',
    endTime = 'end_time',
    action = 'action',
    sourceNamespace = 'source_namespace',
    sourceName = 'source_name',
    destNamespace = 'dest_namespace',
    destName = 'dest_name',
    protocol = 'protocol',
    destPort = 'dest_port',
    reporter = 'reporter',
}

export type ColumnName = (typeof Columns)[keyof typeof Columns];

type Column = { Header: ColumnName } & {
    [key: string]: any;
};

export const getStandardColumns = (): Column[] => [
    {
        Header: Columns.startTime,
        width: 40,
        minWidth: 20,
        accessor: 'start_time',
        Cell: ({ row }: CellProps<FlowLog>) => {
            const { start_time } = row.original;

            return new Date(start_time).toLocaleTimeString();
        },
        checked: true,
        sortType: (rowA: Row<FlowLog>, rowB: Row<FlowLog>) =>
            rowA.original.start_time.getTime() -
            rowB.original.start_time.getTime(),
    },
    {
        Header: Columns.endTime,
        width: 40,
        minWidth: 20,
        accessor: 'end_time',
        Cell: ({ row }: CellProps<FlowLog>) => {
            const { end_time } = row.original;

            return new Date(end_time).toLocaleTimeString();
        },
        checked: true,
        sortType: (rowA: Row<FlowLog>, rowB: Row<FlowLog>) =>
            rowA.original.end_time.getTime() - rowB.original.end_time.getTime(),
    },
    {
        Header: Columns.action,
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
        Header: Columns.sourceNamespace,
        width: 70,
        minWidth: 30,
        accessor: 'source_namespace',
        checked: true,
    },
    {
        Header: Columns.sourceName,
        width: 100,
        minWidth: 50,
        accessor: 'source_name',
        checked: true,
    },
    {
        Header: Columns.destNamespace,
        width: 70,
        minWidth: 30,
        accessor: 'dest_namespace',
        checked: true,
    },
    {
        Header: Columns.destName,
        width: 100,
        minWidth: 50,
        accessor: 'dest_name',
        checked: true,
    },
    {
        Header: Columns.protocol,
        width: 40,
        minWidth: 20,
        accessor: 'protocol',
        checked: true,
    },
    {
        Header: Columns.destPort,
        width: 40,
        minWidth: 20,
        accessor: 'dest_port',
        checked: true,
    },
    {
        Header: Columns.reporter,
        width: 40,
        minWidth: 20,
        accessor: 'reporter',
        checked: true,
        Cell: ({ row }: CellProps<FlowLog>) => {
            const { reporter } = row.original;

            return ReporterLabels[reporter as keyof typeof ReporterLabels];
        },
    },
];

export const getTableColumns = (
    onColumnCustomizerOpen: () => void,
    columns: Column[],
) => [
    {
        ...DataTable.expandoTableColumn,
        disableReordering: true,
        checked: true,
    },
    ...columns,
    {
        Header: (
            <Tooltip label='Customize columns' hasArrow placement='top'>
                <Button
                    variant={'solid'}
                    borderRadius={0}
                    mr='0'
                    onClick={() => {
                        onColumnCustomizerOpen();
                    }}
                    minHeight='36px'
                >
                    <Icon as={AddIcon} />
                </Button>
            </Tooltip>
        ),
        disableSortBy: true,
        maxWidth: 45,
        accessor: 'customizer_header',
        disableResizing: true,
        disableReordering: true,
        checked: true,
    },
];
