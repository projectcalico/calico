import { fireEvent, render, screen, within } from '@/test-utils/helper';
import OmniFilters from '..';
import { OmniFilterKeys } from '@/utils/omniFilter';

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
        }: any) => {
            return (
                <div data-testId={filterLabel}>
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
};

jest.useFakeTimers();

describe('<OmniFilters />', () => {
    it('should clear the filter', () => {
        const mockOnChange = jest.fn();
        render(<OmniFilters {...defaultProps} onChange={mockOnChange} />);

        const omniFilter = within(screen.getByTestId('Policy'));
        fireEvent.click(omniFilter.getByText('on clear'));

        expect(mockOnChange).toHaveBeenCalledWith({
            filterId: 'policy',
            filterLabel: '',
            filters: [],
            operator: undefined,
        });
    });

    it('should call onReady', () => {
        const mockOnRequestFilterData = jest.fn();
        render(
            <OmniFilters
                {...defaultProps}
                onRequestFilterData={mockOnRequestFilterData}
                omniFilterData={{
                    ...defaultProps.omniFilterData,
                    policy: { filters: null, isLoading: false },
                }}
            />,
        );

        const omniFilter = within(screen.getByTestId('Policy'));
        fireEvent.click(omniFilter.getByText('on ready'));

        expect(mockOnRequestFilterData).toHaveBeenCalledWith({
            filterParam: 'policy',
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

        const omniFilter = within(screen.getByTestId('Policy'));
        fireEvent.click(omniFilter.getByText('on search'));

        jest.advanceTimersByTime(1000);
        fireEvent.click(omniFilter.getByText('on search'));

        jest.advanceTimersByTime(1000);

        expect(mockOnRequestFilterData).toHaveBeenCalledWith({
            filterParam: 'policy',
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

        const omniFilter = within(screen.getByTestId('Policy'));
        fireEvent.click(omniFilter.getByText('on clear search'));

        expect(mockOnRequestFilterData).toHaveBeenCalledWith({
            filterParam: 'policy',
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

        const omniFilter = within(screen.getByTestId('Policy'));
        fireEvent.click(omniFilter.getByText('request more'));

        expect(mockOnRequestNextPage).toHaveBeenCalledWith('policy');
    });

    it('should call onMultiChange when port/ protocol changes', () => {
        const mockOnMultiChange = jest.fn();
        render(
            <OmniFilters {...defaultProps} onMultiChange={mockOnMultiChange} />,
        );

        const event = { port: 8080, protocol: 'proto' };
        PortOmniFilterMock.onChange(event);

        expect(mockOnMultiChange).toHaveBeenCalledWith(
            [OmniFilterKeys.protocol, OmniFilterKeys.port],
            [event.protocol, event.port],
        );
    });

    it('should handle when port/ protocol values are provided', () => {
        const port = '1234';
        const protocol = 'tcp';
        const mockOnMultiChange = jest.fn();
        render(
            <OmniFilters
                {...defaultProps}
                onMultiChange={mockOnMultiChange}
                selectedValues={{ port: [port], protocol: [protocol] }}
            />,
        );

        expect(screen.getByText(`Port ${port} ${protocol}`));
    });
});
