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
    onClear: jest.fn(),
};
jest.mock(
    '@/features/flowLogs/components/PolicyOmniFilter',
    () =>
        ({ filterLabel, onChange, onClear }: any) => {
            PolicyOmniFilterMock.onChange = onChange;
            PolicyOmniFilterMock.onClear = onClear;
            return <div>{filterLabel} filter</div>;
        },
);

const ActionOmniFilterMock = {
    onChange: jest.fn(),
};
jest.mock(
    '@/features/flowLogs/components/ActionOmniFilter',
    () =>
        ({ onChange, value }: any) => {
            ActionOmniFilterMock.onChange = onChange;
            return (
                <div>
                    Mock ActionOmniFilter {value.action ?? 'no action'}{' '}
                    {value.staged_action ?? 'no staged action'}
                </div>
            );
        },
);

const StartTimeOmniFilterMock = {
    onChange: jest.fn(),
    onReset: jest.fn(),
};
jest.mock(
    '@/features/flowLogs/components/StartTimeOmniFilter',
    () =>
        ({ filterLabel, onChange, onReset, selectedFilters, value }: any) => {
            StartTimeOmniFilterMock.onChange = onChange;
            StartTimeOmniFilterMock.onReset = onReset;
            return (
                <div>
                    {filterLabel} value={value} selected=
                    {selectedFilters === null
                        ? 'none'
                        : selectedFilters.join(',')}
                </div>
            );
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

    it('should clear the policy filter', () => {
        const mockOnChange = jest.fn();
        render(<OmniFilters {...defaultProps} onChange={mockOnChange} />);

        act(() => {
            PolicyOmniFilterMock.onClear();
        });

        expect(mockOnChange).toHaveBeenCalledWith('policy', []);
    });

    it('should show the reset button and call onReset when a filter is selected', () => {
        const mockOnReset = jest.fn();
        render(
            <OmniFilters
                {...defaultProps}
                onReset={mockOnReset}
                selectedValues={{
                    policy: [{ name: 'allow-nginx', namespace: 'prod' }],
                }}
            />,
        );

        fireEvent.click(screen.getByTestId('omnifilterlist-reset'));

        expect(mockOnReset).toHaveBeenCalled();
    });

    it('should clear port and protocol when the port filter is emptied', () => {
        const mockOnMultiChange = jest.fn();
        render(
            <OmniFilters {...defaultProps} onMultiChange={mockOnMultiChange} />,
        );

        act(() => {
            PortOmniFilterMock.onChange({ port: '', protocol: '' });
        });

        expect(mockOnMultiChange).toHaveBeenCalledWith({
            [OmniFilterKeys.protocol]: [],
            [OmniFilterKeys.dest_port]: [],
        });
    });

    it('should pass selected action values to the action filter', () => {
        render(
            <OmniFilters
                {...defaultProps}
                selectedValues={{
                    action: ['Allow'],
                    staged_action: ['Deny'],
                }}
            />,
        );

        expect(
            screen.getByText('Mock ActionOmniFilter Allow Deny'),
        ).toBeInTheDocument();
    });

    it('should pass the selected start time to the start time filter', () => {
        render(
            <OmniFilters
                {...defaultProps}
                selectedValues={{ start_time: ['15'] }}
                startTime={15}
            />,
        );

        expect(
            screen.getByText('Start Time value=15 selected=15'),
        ).toBeInTheDocument();
    });

    it('should clear the start time filter on reset', () => {
        const mockOnChange = jest.fn();
        render(
            <OmniFilters
                {...defaultProps}
                onChange={mockOnChange}
                selectedValues={{ start_time: ['15'] }}
            />,
        );

        act(() => {
            StartTimeOmniFilterMock.onReset();
        });

        expect(mockOnChange).toHaveBeenCalledWith('start_time', []);
    });

    it('should call onChange with the new start time', () => {
        const mockOnChange = jest.fn();
        render(<OmniFilters {...defaultProps} onChange={mockOnChange} />);

        act(() => {
            StartTimeOmniFilterMock.onChange({
                filterId: 'start_time',
                filters: [{ label: '30', value: '30' }],
            });
        });

        expect(mockOnChange).toHaveBeenCalledWith('start_time', ['30']);
    });
});
