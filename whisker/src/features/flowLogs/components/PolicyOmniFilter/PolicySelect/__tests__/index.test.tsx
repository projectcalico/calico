import { act, render, screen } from '@/test-utils/helper';
import { FilterKey } from '@/utils/omniFilter';
import PolicySelect from '..';

const mockFetchData = jest.fn();
let mockData: Record<string, any> = {};
jest.mock('@/hooks/omniFilters', () => ({
    useOmniFilterQuery: () => ({
        data: mockData,
        fetchData: mockFetchData,
    }),
}));

const mockDebounce = jest.fn((_key: string, fn: () => void) => fn());
jest.mock('@/hooks', () => ({
    useDebouncedCallback: () => mockDebounce,
}));

let omniFilterProps: Record<string, any> = {};
jest.mock('@/libs/tigera/ui-components/components/common/OmniFilter', () => {
    const component = (props: any) => {
        omniFilterProps = props;
        return (
            <div data-testid='omni-filter'>
                <button
                    data-testid='change-btn'
                    onClick={() =>
                        props.onChange({
                            filterId: props.filterId,
                            filterLabel: '',
                            operator: undefined,
                            filters: [
                                {
                                    label: 'NetworkPolicy',
                                    value: 'NetworkPolicy',
                                },
                            ],
                        })
                    }
                />
                <button
                    data-testid='clear-btn'
                    onClick={() => props.onClear()}
                />
                <button
                    data-testid='ready-btn'
                    onClick={() => props.onReady?.()}
                />
                <button
                    data-testid='search-btn'
                    onClick={() =>
                        props.onRequestSearch?.(props.filterId, 'net')
                    }
                />
                <button
                    data-testid='search-empty-btn'
                    onClick={() => props.onRequestSearch?.(props.filterId, '')}
                />
                <button
                    data-testid='more-btn'
                    onClick={() => props.onRequestMore?.(props.filterId, '')}
                />
            </div>
        );
    };
    component.displayName = 'OmniFilter';
    return { __esModule: true, default: component };
});

const defaultProps = {
    filterKey: FilterKey.policyKind as any,
    value: null as any,
    onChange: jest.fn(),
    placeholder: 'Select...',
};

describe('<PolicySelect />', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        mockData = {
            filters: [
                { label: 'NetworkPolicy', value: 'NetworkPolicy' },
                { label: 'GlobalNetworkPolicy', value: 'GlobalNetworkPolicy' },
            ],
            isLoading: false,
            total: 2,
        };
    });

    it('renders the OmniFilter', () => {
        render(<PolicySelect {...defaultProps} />);

        expect(screen.getByTestId('omni-filter')).toBeInTheDocument();
    });

    it('passes filterId and filterLabel to OmniFilter', () => {
        render(<PolicySelect {...defaultProps} />);

        expect(omniFilterProps.filterId).toBe(FilterKey.policyKind);
        expect(omniFilterProps.filterLabel).toBe('');
    });

    it('passes selectedFilters as empty when value is null', () => {
        render(<PolicySelect {...defaultProps} value={null} />);

        expect(omniFilterProps.selectedFilters).toEqual([]);
    });

    it('passes selectedFilters with value when provided', () => {
        const value = { label: 'NetworkPolicy', value: 'NetworkPolicy' };
        render(<PolicySelect {...defaultProps} value={value} />);

        expect(omniFilterProps.selectedFilters).toEqual([value]);
    });

    it('calls onChange with the first filter on change', () => {
        render(<PolicySelect {...defaultProps} />);

        act(() => {
            screen.getByTestId('change-btn').click();
        });

        expect(defaultProps.onChange).toHaveBeenCalledWith({
            label: 'NetworkPolicy',
            value: 'NetworkPolicy',
        });
    });

    it('calls onChange with null on clear', () => {
        render(<PolicySelect {...defaultProps} />);

        act(() => {
            screen.getByTestId('clear-btn').click();
        });

        expect(defaultProps.onChange).toHaveBeenCalledWith(null);
    });

    it('calls fetchData on ready', () => {
        render(<PolicySelect {...defaultProps} />);

        act(() => {
            screen.getByTestId('ready-btn').click();
        });

        expect(mockFetchData).toHaveBeenCalled();
    });

    it('calls fetchData(null) on request more', () => {
        render(<PolicySelect {...defaultProps} />);

        act(() => {
            screen.getByTestId('more-btn').click();
        });

        expect(mockFetchData).toHaveBeenCalledWith(null);
    });

    it('calls fetchData via debounce on search', () => {
        render(<PolicySelect {...defaultProps} />);

        act(() => {
            screen.getByTestId('search-btn').click();
        });

        expect(mockDebounce).toHaveBeenCalledWith('net', expect.any(Function));
        expect(mockFetchData).toHaveBeenCalled();
    });

    it('calls fetchData immediately without debouncing when search is cleared', () => {
        render(<PolicySelect {...defaultProps} />);

        act(() => {
            screen.getByTestId('search-empty-btn').click();
        });

        expect(mockDebounce).not.toHaveBeenCalled();
        expect(mockFetchData).toHaveBeenCalled();
    });

    it('defaults filters and totalItems when data is not loaded yet', () => {
        mockData = {
            filters: undefined,
            isLoading: true,
            total: undefined,
        };
        render(<PolicySelect {...defaultProps} />);

        expect(omniFilterProps.filters).toEqual([]);
        expect(omniFilterProps.totalItems).toBe(0);
    });

    it('passes showSearch to OmniFilter', () => {
        render(<PolicySelect {...defaultProps} showSearch={false} />);

        expect(omniFilterProps.showSearch).toBe(false);
    });

    it('defaults showSearch to true', () => {
        render(<PolicySelect {...defaultProps} />);

        expect(omniFilterProps.showSearch).toBe(true);
    });

    it('renders "Select..." placeholder when value is null', () => {
        render(<PolicySelect {...defaultProps} value={null} />);

        expect(
            omniFilterProps.partsProps.triggerProps.customContent.props
                .children,
        ).toBe('Select...');
    });

    it('renders value label when value is provided', () => {
        const value = { label: 'NetworkPolicy', value: 'NetworkPolicy' };
        render(<PolicySelect {...defaultProps} value={value} />);

        expect(
            omniFilterProps.partsProps.triggerProps.customContent.props
                .children,
        ).toBe('NetworkPolicy');
    });

    it('sets listType to select', () => {
        render(<PolicySelect {...defaultProps} />);

        expect(omniFilterProps.listType).toBe('select');
    });
});
