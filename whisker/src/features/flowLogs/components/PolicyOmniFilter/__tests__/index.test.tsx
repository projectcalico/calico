import { act, fireEvent, render, screen } from '@/test-utils/helper';
import { FilterKey } from '@/utils/omniFilter';
import PolicyOmniFilter from '..';
import { transformToFilterOptions, transformToQueries } from '../utils';

const FilterListMock = { onChange: jest.fn() };
jest.mock('../QueryList', () => {
    const component = ({ queries, onChange }: any) => {
        FilterListMock.onChange = onChange;
        return <div data-testid='filter-list'>{JSON.stringify(queries)}</div>;
    };
    component.displayName = 'FilterList';
    return { __esModule: true, default: component };
});

const NoPolicyCheckboxMock = { onChange: jest.fn() };
jest.mock('../NoPolicyCheckbox', () => {
    const component = ({ value, onChange }: any) => {
        NoPolicyCheckboxMock.onChange = onChange;
        return (
            <div data-testid='no-policy-checkbox' data-checked={value}>
                NoPolicyCheckbox
            </div>
        );
    };
    component.displayName = 'NoPolicyCheckbox';
    return { __esModule: true, default: component };
});

jest.mock('../utils', () => ({
    transformToQueries: jest.fn(() => [{}]),
    transformToFilterOptions: jest.fn(() => []),
}));

const defaultProps = {
    onChange: jest.fn(),
    onClear: jest.fn(),
    selectedFilters: [] as any[],
    filterId: FilterKey.policy,
};

const openPopover = () => {
    fireEvent.click(screen.getByTestId('policy-omni-filter-button-trigger'));
};

describe('<PolicyOmniFilter />', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('renders trigger with Policy label', () => {
        render(<PolicyOmniFilter {...defaultProps} />);

        expect(screen.getByText('Policy')).toBeInTheDocument();
    });

    it('does not show badge when no filters are selected', () => {
        render(<PolicyOmniFilter {...defaultProps} />);

        expect(screen.queryByText(/\+\d/)).not.toBeInTheDocument();
    });

    it('shows badge with filter count when filters are selected', () => {
        render(
            <PolicyOmniFilter
                {...defaultProps}
                selectedFilters={[
                    { kind: 'NetworkPolicy', namespace: 'default' },
                    { kind: 'GlobalNetworkPolicy' },
                ]}
            />,
        );

        expect(screen.getByText('+2')).toBeInTheDocument();
    });

    it('renders FilterList and NoPolicyCheckbox when popover is open', () => {
        render(<PolicyOmniFilter {...defaultProps} />);
        openPopover();

        expect(screen.getByTestId('filter-list')).toBeInTheDocument();
        expect(screen.getByTestId('no-policy-checkbox')).toBeInTheDocument();
    });

    it('hides FilterList when selected filter is no-policy', () => {
        render(
            <PolicyOmniFilter
                {...defaultProps}
                selectedFilters={[{ kind: 'Profile' }]}
            />,
        );
        openPopover();

        expect(screen.queryByTestId('filter-list')).not.toBeInTheDocument();
        expect(screen.getByTestId('no-policy-checkbox')).toBeInTheDocument();
    });

    it('calls onClear when clear button is clicked', () => {
        render(<PolicyOmniFilter {...defaultProps} />);
        openPopover();

        fireEvent.click(screen.getByText('Clear all'));

        expect(defaultProps.onClear).toHaveBeenCalled();
    });

    it('calls onChange with transformed filter options on apply', () => {
        const mockFilters = [{ kind: 'NetworkPolicy', name: 'my-policy' }];
        (transformToFilterOptions as jest.Mock).mockReturnValue(mockFilters);

        render(<PolicyOmniFilter {...defaultProps} />);
        openPopover();

        fireEvent.click(screen.getByText('Update'));

        expect(defaultProps.onChange).toHaveBeenCalledWith(
            FilterKey.policy,
            JSON.stringify(mockFilters),
        );
    });

    it('calls onChange with empty string when filter options are empty', () => {
        (transformToFilterOptions as jest.Mock).mockReturnValue([]);

        render(<PolicyOmniFilter {...defaultProps} />);
        openPopover();

        fireEvent.click(screen.getByText('Update'));

        expect(defaultProps.onChange).toHaveBeenCalledWith(
            FilterKey.policy,
            '',
        );
    });

    it('calls onChange with no-policy value when no-policy is checked', () => {
        render(
            <PolicyOmniFilter
                {...defaultProps}
                selectedFilters={[{ kind: 'Profile' }]}
            />,
        );
        openPopover();

        fireEvent.click(screen.getByText('Update'));

        expect(defaultProps.onChange).toHaveBeenCalledWith(
            FilterKey.policy,
            '[{"kind": "Profile"}]',
        );
    });

    it('syncs query state from selectedFilters when trigger is clicked', () => {
        const selectedFilters = [{ kind: 'NetworkPolicy', name: 'my-policy' }];
        render(
            <PolicyOmniFilter
                {...defaultProps}
                selectedFilters={selectedFilters}
            />,
        );

        openPopover();

        expect(transformToQueries).toHaveBeenCalledWith(selectedFilters);
    });

    it('sets no-policy checked when trigger is clicked and filter is no-policy', () => {
        render(
            <PolicyOmniFilter
                {...defaultProps}
                selectedFilters={[{ kind: 'Profile' }]}
            />,
        );

        openPopover();

        expect(screen.getByTestId('no-policy-checkbox')).toHaveAttribute(
            'data-checked',
            'true',
        );
    });

    it('hides FilterList when NoPolicyCheckbox is toggled on', () => {
        render(<PolicyOmniFilter {...defaultProps} />);
        openPopover();

        expect(screen.getByTestId('filter-list')).toBeInTheDocument();

        act(() => {
            NoPolicyCheckboxMock.onChange(true);
        });

        expect(screen.queryByTestId('filter-list')).not.toBeInTheDocument();
    });

    it('shows FilterList when NoPolicyCheckbox is toggled off', () => {
        render(
            <PolicyOmniFilter
                {...defaultProps}
                selectedFilters={[{ kind: 'Profile' }]}
            />,
        );
        openPopover();

        expect(screen.queryByTestId('filter-list')).not.toBeInTheDocument();

        act(() => {
            NoPolicyCheckboxMock.onChange(false);
        });

        expect(screen.getByTestId('filter-list')).toBeInTheDocument();
    });
});
