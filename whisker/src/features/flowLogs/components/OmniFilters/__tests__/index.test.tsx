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
                </div>
            );
        },
);

const defaultProps = {
    omniFilterData: {
        namespace: {
            filters: [],
            isLoading: false,
        },
        policy: {
            filters: [],
            isLoading: false,
        },
        src_name: {
            filters: [],
            isLoading: false,
        },
        dst_name: {
            filters: [],
            isLoading: false,
        },
    },
    selectedOmniFilters: {
        namespace: [],
        policy: [],
        src_name: [],
        dst_name: [],
    },
    onChange: jest.fn(),
    onReset: jest.fn(),
    onRequestFilterData: jest.fn(),
    onRequestNextPage: jest.fn(),
};

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

    it('should request data when opened for the first time', () => {
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

    it('should not call onReady when there is data', () => {
        const mockOnRequestFilterData = jest.fn();
        render(
            <OmniFilters
                {...defaultProps}
                onRequestFilterData={mockOnRequestFilterData}
            />,
        );

        const omniFilter = within(screen.getByTestId('Policy'));
        fireEvent.click(omniFilter.getByText('on ready'));

        expect(mockOnRequestFilterData).not.toHaveBeenCalled();
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

        expect(mockOnRequestFilterData).toHaveBeenCalledWith({
            filterParam: 'policy',
            page: 1,
            searchOption: 'search-criteria',
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
