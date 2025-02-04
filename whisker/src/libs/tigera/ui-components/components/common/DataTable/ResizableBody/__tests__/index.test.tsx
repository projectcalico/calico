import { fireEvent, render, screen, within } from '@/test-utils/helper';
import { Table } from '@chakra-ui/react';
import ResizableBody, { getTableStateReducer } from '../index';

const mockTableRowData = {
    getRowProps: (input: any) => input,
    getToggleRowExpandedProps: () => ({
        'data-mockgettogglerowexpandedprops': 'exampleValue',
    }),
    cells: [
        {
            getCellProps: () => ({}),
            render: () => 'mockRenderedCell',
        },
    ],
};

describe('<ResizableBody/>', () => {
    it('renders', () => {
        const mockRowData = [
            {
                ...mockTableRowData,
                isExpanded: false,
                original: { id: 'mockRowName' },
                cells: [
                    {
                        getCellProps: () => ({}),
                        render: () => 'mockRenderedRow1Cell1',
                    },
                    {
                        getCellProps: () => ({}),
                        render: () => 'mockRenderedRow1Cell2',
                    },
                ],
            },
            {
                ...mockTableRowData,
                original: { id: 'mockRowName2' },
                cells: [
                    {
                        getCellProps: () => ({}),
                        render: () => 'mockRenderedRow2Cell1',
                    },
                    {
                        getCellProps: () => ({}),
                        render: () => 'mockRenderedRow2Cell2',
                    },
                ],
            },
        ];

        render(
            <Table as='div'>
                <ResizableBody
                    rows={mockRowData}
                    getTableBodyProps={() => ({
                        'data-test-mocked_getTableBodyProps': 'exampleValue',
                        key: 'mockedKeyItem',
                    })}
                    prepareRow={() => 'mocked_prepared_row'}
                    visibleColumns={[]}
                    data={[{ mockedData: 'exampleValue' }]}
                />
            </Table>,
        );

        const { getByText } = within(screen.getAllByTestId('cell-body')[0]);
        expect(getByText('mockRenderedRow1Cell1')).toBeInTheDocument();
    });

    it('renders an expando, and initialized for use in a fixed header table', () => {
        const mockRowData = [
            {
                isExpanded: true,
                original: { id: 'mockRowName' },
                ...mockTableRowData,
            },
        ];

        render(
            <Table as='div'>
                <ResizableBody
                    hasFixedHeader={true}
                    rows={mockRowData}
                    renderRowSubComponent={({ data }: { data: any }) => (
                        <div>mockedDataOutputted: {JSON.stringify(data)}</div>
                    )}
                    getTableBodyProps={() => ({
                        'data-test-mocked_getTableBodyProps': 'exampleValue',
                        key: 'mockedKeyItem',
                    })}
                    prepareRow={() => 'mocked_prepared_row'}
                    onRowClicked={() => 'click click'}
                    visibleColumns={[]}
                    data={[{ mockedData: 'exampleValue' }]}
                />
            </Table>,
        );
        expect(
            screen.getByText(
                'mockedDataOutputted: [{"mockedData":"exampleValue"}]',
            ),
        ).toBeInTheDocument();
        fireEvent.keyUp(screen.getByTestId('cell-body'), { key: 'ArrowDown' });
        fireEvent.keyDown(screen.getByTestId('cell-body'), {
            key: 'ArrowDown',
        });

        expect(
            screen.getByText(
                'mockedDataOutputted: [{"mockedData":"exampleValue"}]',
            ),
        ).toBeInTheDocument();
    });

    it('renders an expando, pointing to alt key data prop', () => {
        const mockRowData = [
            {
                isExpanded: true,
                original: { name: 'mockRowName' },
                ...mockTableRowData,
            },
        ];

        render(
            <Table as='div'>
                <ResizableBody
                    keyProp='name'
                    rows={mockRowData}
                    renderRowSubComponent={({ data }: { data: any }) => (
                        <div>mockedDataOutputted: {JSON.stringify(data)}</div>
                    )}
                    getTableBodyProps={() => ({
                        'data-test-mocked_getTableBodyProps': 'exampleValue',
                        key: 'mockedKeyItem',
                    })}
                    prepareRow={() => 'mocked_prepared_row'}
                    visibleColumns={[]}
                    data={[{ mockedData: 'exampleValue' }]}
                />
            </Table>,
        );

        expect(
            screen.getByText(
                'mockedDataOutputted: [{"mockedData":"exampleValue"}]',
            ),
        ).toBeInTheDocument();
    });

    it('renders a tablebody, exercises checkbox behaviour', () => {
        const mockCallBack = jest.fn();
        const mockRowData = [
            {
                isExpanded: false,
                original: { id: 'mockChecked1' },
                ...mockTableRowData,
            },
            {
                isExpanded: false,
                original: { id: 'mockChecked2' },
                ...mockTableRowData,
            },
            {
                isExpanded: false,
                original: { id: 'mockChecked3' },
                ...mockTableRowData,
            },
        ];

        render(
            <Table as='div'>
                <ResizableBody
                    onRowChecked={mockCallBack}
                    checkedRows={[
                        'mockChecked1',
                        'mockChecked2',
                        'mockChecked3',
                    ]}
                    checkAriaLabel={'mockAriaCheckboxLabel'}
                    keyProp='id'
                    rows={mockRowData}
                    renderRowSubComponent={() => <div />}
                    getTableBodyProps={() => ({
                        'data-test-mocked_getTableBodyProps': 'exampleValue',
                        key: 'mockedKeyItem',
                    })}
                    prepareRow={() => 'mocked_prepared_row'}
                    visibleColumns={[]}
                    data={[{ mockedData: 'exampleValue' }]}
                />
            </Table>,
        );

        expect(screen.getAllByTestId('cell-checkbox')[0]).toBeInTheDocument();
        fireEvent.click(screen.getAllByTestId('cell-checkbox')[0]);

        expect(mockCallBack).toBeCalledTimes(1);
    });

    it('getTableStateReducer', () => {
        expect(
            getTableStateReducer({ mock: 'newstate' }, { type: 'invalid' }, {}),
        ).toEqual({ mock: 'newstate' });

        const mockNewState = {
            expanded: { token1: true, token2: false, token3: true },
        };
        const mockPrevState = {
            expanded: { token1: true, token2: true },
        };

        expect(
            getTableStateReducer(
                mockNewState,
                { type: 'toggleRowExpanded' },
                mockPrevState,
            ),
        ).toEqual({
            expanded: { token3: true },
        });
    });
});
