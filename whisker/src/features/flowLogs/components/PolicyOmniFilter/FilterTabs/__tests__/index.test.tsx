import { FilterKey } from '@/utils/omniFilter';
import userEvent from '@testing-library/user-event';
import { render, screen } from '../../../../../../../test-utils/helper';
import FilterTabs from '../index';

// Mock the FilterChecklist component
jest.mock('../../../FilterChecklist', () => {
    return function MockFilterChecklist({
        testId,
        filterId,
        label,
        selectedValues,
        onChange,
        onClear,
    }: any) {
        return (
            <div data-testid={`${testId}-filter-checklist`}>
                <div data-testid={`${testId}-label`}>{label}</div>
                <div data-testid={`${testId}-selected-count`}>
                    {selectedValues?.length || 0}
                </div>
                <button
                    data-testid={`${testId}-change-button`}
                    onClick={() =>
                        onChange({
                            filterId,
                            filterLabel: label,
                            operator: undefined,
                            filters: [{ label: 'test', value: 'test' }],
                        })
                    }
                >
                    Change Filter
                </button>
                <button
                    data-testid={`${testId}-clear-button`}
                    onClick={() => onClear(filterId)}
                >
                    Clear Filter
                </button>
            </div>
        );
    };
});

describe('<FilterTabs />', () => {
    const defaultProps = {
        filterId: FilterKey.policy,
        values: {
            [FilterKey.policy]: ['policy1', 'policy2'],
            [FilterKey.policyNamespace]: ['ns1'],
            [FilterKey.policyTier]: [],
            [FilterKey.policyKind]: ['kind1', 'kind2', 'kind3'],
        },
        filterQuery: {
            policy: ['policy1'],
            policyNamespace: ['ns1'],
        } as any,
        onChange: jest.fn(),
        onClear: jest.fn(),
    };

    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('renders all filter tabs with correct labels and badge counts', () => {
        render(<FilterTabs {...defaultProps} />);

        // Check that all filter tabs are rendered with correct labels using role queries
        // The tab names include the badge numbers
        expect(
            screen.getByRole('tab', { name: 'Policy 2' }),
        ).toBeInTheDocument();
        expect(
            screen.getByRole('tab', { name: 'Namespace 1' }),
        ).toBeInTheDocument();
        expect(screen.getByRole('tab', { name: 'Tier' })).toBeInTheDocument();
        expect(screen.getByRole('tab', { name: 'Kind 3' })).toBeInTheDocument();

        // Check badge counts for tabs with values by looking for badge elements
        const badges = screen
            .getAllByText('2')
            .filter((el) => el.className?.includes('chakra-badge'));
        expect(badges).toHaveLength(1); // Only one badge with "2"

        const badges1 = screen
            .getAllByText('1')
            .filter((el) => el.className?.includes('chakra-badge'));
        expect(badges1).toHaveLength(1); // Only one badge with "1"

        const badges3 = screen
            .getAllByText('3')
            .filter((el) => el.className?.includes('chakra-badge'));
        expect(badges3).toHaveLength(1); // Only one badge with "3"
        // Tier should not have a badge since it has no values
    });

    it('renders FilterChecklist components for each tab with correct props', async () => {
        const user = userEvent.setup();
        render(<FilterTabs {...defaultProps} />);

        // Only the active tab (policy) should be visible initially
        expect(
            screen.getByTestId('policy-filter-checklist'),
        ).toBeInTheDocument();

        // Check that the correct label is passed for the active tab
        expect(screen.getByTestId('policy-label')).toHaveTextContent('Policy');

        // Check selected values are passed correctly for the active tab
        expect(screen.getByTestId('policy-selected-count')).toHaveTextContent(
            '2',
        );

        // Switch to other tabs to test their content
        const namespaceTab = screen.getByRole('tab', { name: 'Namespace 1' });
        await user.click(namespaceTab);
        expect(
            screen.getByTestId('policyNamespace-filter-checklist'),
        ).toBeInTheDocument();
        expect(screen.getByTestId('policyNamespace-label')).toHaveTextContent(
            'Namespace',
        );
        expect(
            screen.getByTestId('policyNamespace-selected-count'),
        ).toHaveTextContent('1');

        const tierTab = screen.getByRole('tab', { name: 'Tier' });
        await user.click(tierTab);
        expect(
            screen.getByTestId('policyTier-filter-checklist'),
        ).toBeInTheDocument();
        expect(screen.getByTestId('policyTier-label')).toHaveTextContent(
            'Tier',
        );
        expect(
            screen.getByTestId('policyTier-selected-count'),
        ).toHaveTextContent('0');

        const kindTab = screen.getByRole('tab', { name: 'Kind 3' });
        await user.click(kindTab);
        expect(
            screen.getByTestId('policyKind-filter-checklist'),
        ).toBeInTheDocument();
        expect(screen.getByTestId('policyKind-label')).toHaveTextContent(
            'Kind',
        );
        expect(
            screen.getByTestId('policyKind-selected-count'),
        ).toHaveTextContent('3');
    });

    it('handles tab switching and passes events correctly', async () => {
        const user = userEvent.setup();
        const onChangeMock = jest.fn();
        const onClearMock = jest.fn();

        render(
            <FilterTabs
                {...defaultProps}
                onChange={onChangeMock}
                onClear={onClearMock}
            />,
        );

        // Click on the Kind tab
        const kindTab = screen.getByRole('tab', { name: 'Kind 3' });
        await user.click(kindTab);

        // Click the change button in the Kind FilterChecklist
        const kindChangeButton = screen.getByTestId('policyKind-change-button');
        await user.click(kindChangeButton);

        // Verify onChange was called with correct event
        expect(onChangeMock).toHaveBeenCalledWith({
            filterId: 'policyKind',
            filterLabel: 'Kind',
            operator: undefined,
            filters: [{ label: 'test', value: 'test' }],
        });

        // Click the clear button in the Kind FilterChecklist
        const kindClearButton = screen.getByTestId('policyKind-clear-button');
        await user.click(kindClearButton);

        // Verify onClear was called with correct filterId
        expect(onClearMock).toHaveBeenCalledWith('policyKind');
    });

    it('handles empty values correctly and shows no badges', () => {
        const emptyValuesProps = {
            ...defaultProps,
            values: {
                [FilterKey.policy]: [],
                [FilterKey.policyNamespace]: [],
                [FilterKey.policyTier]: [],
                [FilterKey.policyKind]: [],
            },
        };

        render(<FilterTabs {...emptyValuesProps} />);

        // All tabs should be rendered using role queries
        expect(screen.getByRole('tab', { name: 'Policy' })).toBeInTheDocument();
        expect(
            screen.getByRole('tab', { name: 'Namespace' }),
        ).toBeInTheDocument();
        expect(screen.getByRole('tab', { name: 'Tier' })).toBeInTheDocument();
        expect(screen.getByRole('tab', { name: 'Kind' })).toBeInTheDocument();

        // No badges should be visible since all values are empty
        // Note: The FilterChecklist mock still shows "0" for selected count, so we check for badge numbers specifically
        expect(screen.queryByText('1')).not.toBeInTheDocument();
        expect(screen.queryByText('2')).not.toBeInTheDocument();
        expect(screen.queryByText('3')).not.toBeInTheDocument();

        // FilterChecklist component for active tab should still be rendered with empty selected values
        expect(screen.getByTestId('policy-selected-count')).toHaveTextContent(
            '0',
        );
    });
});
