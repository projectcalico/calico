import { fireEvent, render, screen } from '@/test-utils/helper';
import { Table } from '@chakra-ui/react';
import ResizableHeader from '../index';

const defaultHeaderProps = {
    getSortByToggleProps: () => true,
    getHeaderProps: () => true,
    render: () => true,
    getResizerProps: () => true,
    Header: 'IP Addresses',
    depth: 0,
    id: 'ipAddresses',
    sortType: 'alphanumeric',
    canSort: true,
    isSorted: true,
    sortDescFirst: false,
    isVisible: true,
    totalVisibleHeaderCount: 1,
};

describe('<ResizableBody/>', () => {
    it('it renders', () => {
        const headerGroups = [
            {
                headers: [
                    {
                        ...defaultHeaderProps,
                        canResize: true,
                        totalVisibleHeaderCount: 1,
                        isResizing: false,
                        isSorted: false,
                        sortedIndex: -1,
                    },
                ],
                getFooterGroupProps: () => true,
                getHeaderGroupProps: () => true,
            },
        ];
        const { asFragment } = render(
            <Table as='div'>
                <ResizableHeader headerGroups={headerGroups} />
            </Table>,
        );
        expect(asFragment()).toMatchSnapshot();
    });

    it('it renders as fixed header and resizing works', () => {
        const headerGroups = [
            {
                headers: [
                    {
                        ...defaultHeaderProps,
                        canResize: true,
                        isResizing: true,
                        isSorted: false,
                        sortedIndex: -1,
                    },
                ],
                getFooterGroupProps: () => true,
                getHeaderGroupProps: () => true,
            },
        ];

        const { asFragment } = render(
            <Table as='div'>
                <ResizableHeader headerGroups={headerGroups} isFixed={true} />
            </Table>,
        );

        fireEvent.click(screen.getAllByTestId('resizer-box')[0]);

        expect(asFragment()).toMatchSnapshot();
    });

    it('it renders and sorting desc works', () => {
        const headerGroups = [
            {
                headers: [
                    {
                        ...defaultHeaderProps,
                        canResize: true,
                        isResizing: false,
                        sortedIndex: 0,
                        isSortedDesc: true,
                    },
                ],
                getFooterGroupProps: () => true,
                getHeaderGroupProps: () => true,
            },
        ];
        const { asFragment } = render(
            <Table as='div'>
                <ResizableHeader headerGroups={headerGroups} />
            </Table>,
        );

        expect(asFragment()).toMatchSnapshot();
    });

    it('it renders and sorting ascending works', () => {
        const headerGroups = [
            {
                headers: [
                    {
                        ...defaultHeaderProps,
                        canResize: true,
                        isResizing: false,
                        sortedIndex: -1,
                        isSortedDesc: false,
                    },
                ],
                getFooterGroupProps: () => true,
                getHeaderGroupProps: () => true,
            },
        ];
        const { asFragment } = render(
            <Table as='div'>
                <ResizableHeader headerGroups={headerGroups} />
            </Table>,
        );

        expect(asFragment()).toMatchSnapshot();
    });

    it('can render sort disabled columns', () => {
        const headerGroups = [
            {
                headers: [
                    {
                        ...defaultHeaderProps,
                        canResize: true,
                        isResizing: false,
                        sortedIndex: -1,
                        isSortedDesc: false,
                        disableSortBy: true,
                    },
                ],
                getFooterGroupProps: () => true,
                getHeaderGroupProps: () => true,
            },
        ];
        const { asFragment } = render(
            <Table as='div'>
                <ResizableHeader headerGroups={headerGroups} />
            </Table>,
        );

        expect(asFragment()).toMatchSnapshot();
    });

    it('it renders a checked column', () => {
        const headerGroups = [
            {
                headers: [
                    {
                        ...defaultHeaderProps,
                        Header: '',
                        depth: 0,
                        id: 'checked',
                    },
                ],
                getFooterGroupProps: () => true,
                getHeaderGroupProps: () => true,
            },
        ];

        const mockCallBack = jest.fn();

        render(
            <Table as='div'>
                <ResizableHeader
                    headerGroups={headerGroups}
                    isAllChecked={false}
                    onAllChecked={mockCallBack}
                    checkedRows={[
                        'mockChecked1',
                        'mockChecked2',
                        'mockChecked3',
                    ]}
                />
            </Table>,
        );

        expect(mockCallBack).toBeCalledTimes(0);

        fireEvent.click(screen.getAllByTestId('column-header')[0]);

        expect(mockCallBack).toBeCalledTimes(1);

        fireEvent.keyUp(screen.getByTestId('column-header'), {
            key: 'Enter',
            keyCode: 32,
        });

        fireEvent.keyUp(screen.getByTestId('column-header'), {
            key: 'Enter',
            keyCode: 13,
        });

        expect(mockCallBack).toBeCalledTimes(3);
    });
});
