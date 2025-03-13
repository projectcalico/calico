import { fireEvent, render, screen, within } from '@/test-utils/helper';
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
    selectedOmniFilters: {
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
            page: 1,
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

        expect(mockOnRequestFilterData).toHaveBeenCalledWith({
            filterParam: 'policy',
            page: 1,
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
            page: 1,
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
});
