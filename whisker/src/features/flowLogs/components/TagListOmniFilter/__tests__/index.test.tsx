import { render, screen, userEvent, waitFor } from '@/test-utils/helper';
import TagListOmniFilter from '..';
import { useOmniFilterQuery } from '@/hooks/omniFilters';

jest.mock('@/hooks/omniFilters', () => ({
    useOmniFilterQuery: jest.fn(),
}));

describe('<TagListOmniFilter />', () => {
    const defaultProps = {
        filterId: 'policyV2Tier',
        label: 'Policy Filter',
        selectedValues: ['filter-value'],
        filterQuery: {},
        onChange: jest.fn(),
        onClear: jest.fn(),
    } as any;

    const fetchDataMock = jest.fn();

    beforeEach(() => {
        jest.clearAllMocks();

        jest.mocked(useOmniFilterQuery).mockReturnValue({
            data: {
                filters: [{ label: 'filter-value', value: 'filter-value' }],
                isLoading: false,
                total: 0,
            },
            fetchData: fetchDataMock,
        });
    });

    it('should render the tag', async () => {
        render(<TagListOmniFilter {...defaultProps} />);

        expect(screen.getByText('filter-value')).toBeInTheDocument();
    });

    it('should call fetch data on filter change', async () => {
        render(<TagListOmniFilter {...defaultProps} />);

        await userEvent.click(screen.getByTestId('omni-tag-list-trigger'));

        await waitFor(() => {
            expect(fetchDataMock).toHaveBeenCalledWith('');
        });

        await userEvent.type(
            screen.getByTestId('omni-filter-search-filter'),
            'foo',
        );

        await waitFor(() => {
            expect(fetchDataMock).toHaveBeenCalledWith(
                JSON.stringify({
                    policyV2Tiers: [{ type: 'Fuzzy', value: 'foo' }],
                }),
            );
        });

        fetchDataMock.mockClear();

        await userEvent.clear(screen.getByTestId('omni-filter-search-filter'));

        await waitFor(() => {
            expect(fetchDataMock).toHaveBeenCalledWith('');
        });
    });

    it('should call onClear', async () => {
        const mockOnClear = jest.fn();
        render(
            <TagListOmniFilter
                {...defaultProps}
                onClear={mockOnClear}
                selectedValues={['filter-value']}
            />,
        );

        await userEvent.click(screen.getByTestId('omni-tag-list-trigger'));

        await userEvent.click(
            screen.getByRole('button', { name: 'Clear selection' }),
        );

        await waitFor(() => {
            expect(mockOnClear).toHaveBeenCalledWith('policyV2Tier');
        });
    });

    it('should request more data', async () => {
        jest.mocked(useOmniFilterQuery).mockReturnValue({
            data: {
                filters: [{ label: 'filter-value', value: 'filter-value' }],
                isLoading: false,
                total: 2,
            },
            fetchData: fetchDataMock,
        });

        render(<TagListOmniFilter {...defaultProps} />);

        await userEvent.click(screen.getByTestId('omni-tag-list-trigger'));

        fetchDataMock.mockClear();

        await userEvent.click(
            screen.getByRole('button', { name: 'Show more' }),
        );

        await waitFor(() => {
            expect(fetchDataMock).toHaveBeenCalledWith(null);
        });
    });
});
