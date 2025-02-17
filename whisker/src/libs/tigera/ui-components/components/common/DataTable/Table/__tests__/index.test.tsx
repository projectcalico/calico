import { render, screen } from '@/test-utils/helper';
import Table from '../index';

const items = [
    { id: 1, name: 'colm' },
    { id: 2, name: 'breff' },
    { id: 3, name: 'soumya' },
    { id: 4, name: 'ronan' },
];

const columnsGenerator = () => [
    {
        Header: '1',
        minWidth: 70,
        accessor: 'id',
        Cell: ({ cell }: any) => cell.value,
    },

    {
        Header: '2',
        minWidth: 220,
        accessor: 'name',
        Cell: ({ cell }: any) => cell.value,
    },
];

describe('<Table/>', () => {
    it('renders data', () => {
        render(
            <Table
                items={items}
                columnsGenerator={columnsGenerator}
                error={undefined}
                expandRowComponent={<div>some div</div>}
                isFetching={false}
                errorLabel={'mock error label'}
                emptyTableLabel={'mock empty table label'}
            />,
        );

        expect(screen.queryByText('colm')).toBeInTheDocument();
    });

    it('renders paginated data', () => {
        render(
            <Table
                items={items}
                columnsGenerator={columnsGenerator}
                error={undefined}
                expandRowComponent={() => <div>EXPANDO</div>}
                isFetching={false}
                errorLabel={'mock error label'}
                emptyTableLabel={'mock empty table label'}
                isPaginated
                pageSize={2}
                page={0}
                selectedRow={{ id: 1 }}
            />,
        );

        expect(screen.queryByText('colm')).toBeInTheDocument();
        expect(screen.queryByText('EXPANDO')).toBeInTheDocument();
    });

    it('renders empty, covering the expand all', () => {
        render(
            <Table
                items={[]}
                columnsGenerator={columnsGenerator}
                error={undefined}
                isFetching={false}
                expandAll={true}
                expandRowComponent={<div>some div</div>}
                errorLabel={'mock error label'}
                emptyTableLabel={'mock empty table label'}
            />,
        );

        expect(
            screen.queryByText('mock empty table label'),
        ).toBeInTheDocument();
    });

    it('renders error', () => {
        render(
            <Table
                items={undefined}
                columnsGenerator={columnsGenerator}
                error={'error'}
                expandRowComponent={<div>some div</div>}
                isFetching={false}
                errorLabel={'mock error label'}
                emptyTableLabel={'mock empty table label'}
            />,
        );

        expect(screen.queryByText('mock error label')).toBeInTheDocument();
    });
});
