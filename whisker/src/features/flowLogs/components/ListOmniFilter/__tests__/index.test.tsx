import { useInfiniteFilterQuery } from '@/features/flowLogs/api';
import {
    act,
    fireEvent,
    renderWithRouter,
    screen,
    within,
} from '@/test-utils/helper';
import { useLocation } from 'react-router-dom';
import ListOmniFilter from '..';

jest.mock('@/features/flowLogs/api', () => ({
    useInfiniteFilterQuery: jest.fn(),
}));

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

const LocationProbe = () => (
    <div data-testid='location-search'>{useLocation().search}</div>
);

const queryResponse = {
    data: undefined,
    fetchNextPage: jest.fn(),
    refetch: jest.fn(),
    isLoading: false,
    isFetchingNextPage: false,
} as any;

const renderListOmniFilter = (
    route: string,
    props: Partial<React.ComponentProps<typeof ListOmniFilter>> = {},
) =>
    renderWithRouter(
        <>
            <ListOmniFilter
                filterId='source_name'
                filterLabel='Source'
                selectedFilters={[]}
                {...props}
            />
            <LocationProbe />
        </>,
        { routes: [route] },
    );

const currentSearch = () => screen.getByTestId('location-search').textContent;

const lastRequestedQuery = () => {
    const [filterId, query] = jest.mocked(useInfiniteFilterQuery).mock
        .lastCall!;
    return { filterId, query };
};

jest.useFakeTimers();

describe('<ListOmniFilter />', () => {
    beforeEach(() => {
        jest.mocked(useInfiniteFilterQuery)
            .mockClear()
            .mockReturnValue(queryResponse);
    });

    it('should clear its values from the URL', () => {
        renderListOmniFilter('/?source_name=web&dest_name=api');

        fireEvent.click(
            within(screen.getByTestId('Source')).getByText('on clear'),
        );

        expect(currentSearch()).toBe('?dest_name=api');
    });

    it('should write the changed selection to the URL', () => {
        renderListOmniFilter('/');

        fireEvent.click(
            within(screen.getByTestId('Source')).getByText('on change'),
        );

        expect(currentSearch()).toBe(
            '?source_name=filter-1&source_name=filter-2',
        );
    });

    it('should request options narrowed by other filters but not its own selection', () => {
        renderListOmniFilter('/?source_name=web&dest_name=api');

        fireEvent.click(
            within(screen.getByTestId('Source')).getByText('on ready'),
        );

        const { filterId, query } = lastRequestedQuery();
        expect(filterId).toBe('source_name');
        expect(JSON.parse(query!)).toEqual({
            dest_names: [{ type: 'Exact', value: 'api' }],
        });
    });

    it('should debounce a search and request it as a fuzzy match', () => {
        renderListOmniFilter('/?dest_name=api');

        act(() => {
            fireEvent.click(
                within(screen.getByTestId('Source')).getByText('on search'),
            );
        });

        expect(lastRequestedQuery().query).toBe(null);

        act(() => {
            jest.advanceTimersByTime(1000);
        });

        expect(JSON.parse(lastRequestedQuery().query!)).toEqual({
            dest_names: [{ type: 'Exact', value: 'api' }],
            source_names: [{ type: 'Fuzzy', value: 'search-criteria' }],
        });
    });

    it('should request immediately when the search is cleared', () => {
        renderListOmniFilter('/?dest_name=api');

        fireEvent.click(
            within(screen.getByTestId('Source')).getByText('on clear search'),
        );

        expect(JSON.parse(lastRequestedQuery().query!)).toEqual({
            dest_names: [{ type: 'Exact', value: 'api' }],
        });
    });

    it('should fetch the next page on request more', () => {
        const fetchNextPageMock = jest.fn();
        jest.mocked(useInfiniteFilterQuery).mockReturnValue({
            ...queryResponse,
            fetchNextPage: fetchNextPageMock,
        });

        renderListOmniFilter('/');

        fireEvent.click(
            within(screen.getByTestId('Source')).getByText('request more'),
        );

        expect(fetchNextPageMock).toHaveBeenCalledTimes(1);
    });
});
