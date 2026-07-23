import { act, fireEvent, render, screen, within } from '@/test-utils/helper';
import { OmniFilterKeys } from '@/utils/omniFilter';
import OmniFilters from '..';

jest.mock(
    '@/libs/tigera/ui-components/components/common/OmniFilter',
    () =>
        ({
            filterLabel,
            onClear,
            onReady,
            onRequestSearch,
            filterId,
            onRequestMore,
            onChange,
        }: any) => {
            return (
                <div data-testid={filterLabel}>
                    <div>{filterLabel}</div>
                    <span onClick={onClear}>on clear</span>
                    <button onClick={onReady}>on ready</button>
                    <button onClick={() => onRequestMore(filterId)}>
                        request more
                    </button>
                    <button
                        onClick={() =>
                            onRequestSearch(filterId, 'search-criteria')
                        }
                    >
                        on search
                    </button>
                    <button onClick={() => onRequestSearch(filterId, '')}>
                        on clear search
                    </button>
                    <button
                        onClick={() =>
                            onChange({
                                filterId,
                                filterLabel,
                                operator: undefined,
                                filters: [
                                    { value: 'filter-1', label: 'filter-1' },
                                    { value: 'filter-2', label: 'filter-2' },
                                ],
                            })
                        }
                    >
                        on change
                    </button>
                </div>
            );
        },
);

const PortOmniFilterMock = {
    onChange: jest.fn(),
};

jest.mock(
    '@/features/flowLogs/components/PortOmniFilter',
    () =>
        ({ filterLabel, onChange, port, protocol }: any) => {
            PortOmniFilterMock.onChange = onChange;
            return (
                <div>
                    {filterLabel} {port} {protocol}
                </div>
            );
        },
);

const PolicyOmniFilterMock = {
    onChange: jest.fn(),
};
jest.mock(
    '@/features/flowLogs/components/PolicyOmniFilter',
    () =>
        ({ filterLabel, onChange }: any) => {
            PolicyOmniFilterMock.onChange = onChange;
            return <div>{filterLabel} filter</div>;
        },
);

const ActionOmniFilterMock = {
    onChange: jest.fn(),
};
jest.mock(
    '@/features/flowLogs/components/ActionOmniFilter',
    () =>
        ({ onChange }: any) => {
            ActionOmniFilterMock.onChange = onChange;
            return <div>Mock ActionOmniFilter</div>;
        },
);

const defaultProps = {
    omniFilterData: {
        source_namespace: {
            filters: [],
            isLoading: false,
        },
        dest_namespace: {
            filters: [],
            isLoading: false,
        },
        policy: {
            filters: [],
            isLoading: false,
        },
        source_name: {
            filters: [],
            isLoading: false,
        },
        dest_name: {
            filters: [],
            isLoading: false,
        },
    },
    selectedListOmniFilters: {
        source_namespace: [],
        dest_namespace: [],
        policy: [],
        source_name: [],
        dest_name: [],
    },
    onChange: jest.fn(),
    onReset: jest.fn(),
    onRequestFilterData: jest.fn(),
    onRequestNextPage: jest.fn(),
    onMultiChange: jest.fn(),
    selectedValues: {},
    startTime: 0,
};

jest.useFakeTimers();

describe('<OmniFilters />', () => {
    it('should clear the filter', () => {
        const mockOnChange = jest.fn();
        render(<OmniFilters {...defaultProps} onChange={mockOnChange} />);

        const omniFilter = within(screen.getByTestId('Source'));
        fireEvent.click(omniFilter.getByText('on clear'));

        expect(mockOnChange).toHaveBeenCalledWith('source_name', []);
    });

    it('should call onChange with filterId and mapped filter values', () => {
        const mockOnChange = jest.fn();
        render(<OmniFilters {...defaultProps} onChange={mockOnChange} />);

        const omniFilter = within(screen.getByTestId('Source'));
        fireEvent.click(omniFilter.getByText('on change'));

        expect(mockOnChange).toHaveBeenCalledWith('source_name', [
            'filter-1',
            'filter-2',
        ]);
    });

    it('should call onChange with value wrapped in an array when policy filter changes', () => {
        const mockOnChange = jest.fn();
        render(<OmniFilters {...defaultProps} onChange={mockOnChange} />);

        act(() => {
            PolicyOmniFilterMock.onChange('policy', 'my-policy');
        });

        expect(mockOnChange).toHaveBeenCalledWith('policy', ['my-policy']);
    });

    it('should call onChange with null when policy filter value is empty', () => {
        const mockOnChange = jest.fn();
        render(<OmniFilters {...defaultProps} onChange={mockOnChange} />);

        act(() => {
            PolicyOmniFilterMock.onChange('policy', '');
        });

        expect(mockOnChange).toHaveBeenCalledWith('policy', null);
    });

    it('should call onReady', () => {
        const mockOnRequestFilterData = jest.fn();
        render(
            <OmniFilters
                {...defaultProps}
                onRequestFilterData={mockOnRequestFilterData}
                omniFilterData={{
                    ...defaultProps.omniFilterData,
                    source_name: { filters: null, isLoading: false },
                }}
            />,
        );

        const omniFilter = within(screen.getByTestId('Source'));
        fireEvent.click(omniFilter.getByText('on ready'));

        expect(mockOnRequestFilterData).toHaveBeenCalledWith({
            filterParam: 'source_name',
            searchOption: '',
        });
    });

    it('should handle search criteria', () => {
        const mockOnRequestFilterData = jest.fn();
        render(
            <OmniFilters
                {...defaultProps}
                onRequestFilterData={mockOnRequestFilterData}
            />,
        );

        const omniFilter = within(screen.getByTestId('Destination'));
        act(() => {
            fireEvent.click(omniFilter.getByText('on search'));
            jest.advanceTimersByTime(1000);
        });

        act(() => {
            fireEvent.click(omniFilter.getByText('on search'));
            jest.advanceTimersByTime(1000);
        });

        expect(mockOnRequestFilterData).toHaveBeenCalledWith({
            filterParam: 'dest_name',
            searchOption: 'search-criteria',
        });
    });

    it('should handle empty search criteria', () => {
        const mockOnRequestFilterData = jest.fn();
        render(
            <OmniFilters
                {...defaultProps}
                onRequestFilterData={mockOnRequestFilterData}
            />,
        );

        const omniFilter = within(screen.getByTestId('Destination'));
        fireEvent.click(omniFilter.getByText('on clear search'));

        expect(mockOnRequestFilterData).toHaveBeenCalledWith({
            filterParam: 'dest_name',
            searchOption: '',
        });
    });

    it('should request more data', () => {
        const mockOnRequestNextPage = jest.fn();
        render(
            <OmniFilters
                {...defaultProps}
                onRequestNextPage={mockOnRequestNextPage}
            />,
        );

        const omniFilter = within(screen.getByTestId('Source'));
        fireEvent.click(omniFilter.getByText('request more'));

        expect(mockOnRequestNextPage).toHaveBeenCalledWith('source_name');
    });

    it('should call onMultiChange when port/ protocol changes', () => {
        const mockOnMultiChange = jest.fn();
        render(
            <OmniFilters {...defaultProps} onMultiChange={mockOnMultiChange} />,
        );

        const event = { port: 8080, protocol: 'proto' };
        PortOmniFilterMock.onChange(event);

        expect(mockOnMultiChange).toHaveBeenCalledWith({
            [OmniFilterKeys.protocol]: [event.protocol],
            [OmniFilterKeys.dest_port]: [event.port],
        });
    });

    it('should handle when port/ protocol values are provided', () => {
        const port = '1234';
        const protocol = 'tcp';
        const mockOnMultiChange = jest.fn();
        render(
            <OmniFilters
                {...defaultProps}
                onMultiChange={mockOnMultiChange}
                selectedValues={{ dest_port: [port], protocol: [protocol] }}
            />,
        );

        expect(screen.getByText(`Port ${port} ${protocol}`));
    });

    it('should handle when action values are provided', () => {
        const mockOnMultiChange = jest.fn();
        render(
            <OmniFilters
                {...defaultProps}
                onMultiChange={mockOnMultiChange}
                selectedValues={{}}
            />,
        );

        act(() => {
            ActionOmniFilterMock.onChange({
                action: 'Allow',
                staged_action: 'Deny',
            });
        });

        expect(mockOnMultiChange).toHaveBeenCalledWith({
            action: ['Allow'],
            staged_action: ['Deny'],
        });
    });

    it('should handle when action values are cleared', () => {
        const mockOnMultiChange = jest.fn();
        render(
            <OmniFilters
                {...defaultProps}
                onMultiChange={mockOnMultiChange}
                selectedValues={{}}
            />,
        );

        act(() => {
            ActionOmniFilterMock.onChange({
                action: '',
                staged_action: '',
            });
        });

        expect(mockOnMultiChange).toHaveBeenCalledWith({
            action: [],
            staged_action: [],
        });
    });
});
