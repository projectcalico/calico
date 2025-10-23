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
        filterId: FilterKey.policyV2,
        values: {
            [FilterKey.policyV2]: ['policy1', 'policy2'],
            [FilterKey.policyV2Namespace]: ['ns1'],
            [FilterKey.policyV2Tier]: [],
            [FilterKey.policyV2Kind]: ['kind1', 'kind2', 'kind3'],
            // Add other required FilterKey properties with empty arrays
            [FilterKey.policy]: [],
            [FilterKey.source_name]: [],
            [FilterKey.source_namespace]: [],
            [FilterKey.dest_name]: [],
            [FilterKey.dest_namespace]: [],
            [FilterKey.start_time]: [],
            [FilterKey.action]: [],
            [FilterKey.dest_port]: [],
            [FilterKey.protocol]: [],
            [FilterKey.reporter]: [],
            [FilterKey.staged_action]: [],
            [FilterKey.pending_action]: [],
        } as Record<FilterKey, string[]>,
        filterQuery: {
            policyV2: ['policy1'],
            policyV2Namespace: ['ns1'],
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
            screen.getByRole('tab', { name: 'Policy V2 2' }),
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

        // Only the active tab (policyV2) should be visible initially
        expect(
            screen.getByTestId('policyV2-filter-checklist'),
        ).toBeInTheDocument();

        // Check that the correct label is passed for the active tab
        expect(screen.getByTestId('policyV2-label')).toHaveTextContent(
            'Policy V2',
        );

        // Check selected values are passed correctly for the active tab
        expect(screen.getByTestId('policyV2-selected-count')).toHaveTextContent(
            '2',
        );

        // Switch to other tabs to test their content
        const namespaceTab = screen.getByRole('tab', { name: 'Namespace 1' });
        await user.click(namespaceTab);
        expect(
            screen.getByTestId('policyV2Namespace-filter-checklist'),
        ).toBeInTheDocument();
        expect(screen.getByTestId('policyV2Namespace-label')).toHaveTextContent(
            'Namespace',
        );
        expect(
            screen.getByTestId('policyV2Namespace-selected-count'),
        ).toHaveTextContent('1');

        const tierTab = screen.getByRole('tab', { name: 'Tier' });
        await user.click(tierTab);
        expect(
            screen.getByTestId('policyV2Tier-filter-checklist'),
        ).toBeInTheDocument();
        expect(screen.getByTestId('policyV2Tier-label')).toHaveTextContent(
            'Tier',
        );
        expect(
            screen.getByTestId('policyV2Tier-selected-count'),
        ).toHaveTextContent('0');

        const kindTab = screen.getByRole('tab', { name: 'Kind 3' });
        await user.click(kindTab);
        expect(
            screen.getByTestId('policyV2Kind-filter-checklist'),
        ).toBeInTheDocument();
        expect(screen.getByTestId('policyV2Kind-label')).toHaveTextContent(
            'Kind',
        );
        expect(
            screen.getByTestId('policyV2Kind-selected-count'),
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
        const kindChangeButton = screen.getByTestId(
            'policyV2Kind-change-button',
        );
        await user.click(kindChangeButton);

        // Verify onChange was called with correct event
        expect(onChangeMock).toHaveBeenCalledWith({
            filterId: 'policyV2Kind',
            filterLabel: 'Kind',
            operator: undefined,
            filters: [{ label: 'test', value: 'test' }],
        });

        // Click the clear button in the Kind FilterChecklist
        const kindClearButton = screen.getByTestId('policyV2Kind-clear-button');
        await user.click(kindClearButton);

        // Verify onClear was called with correct filterId
        expect(onClearMock).toHaveBeenCalledWith('policyV2Kind');
    });

    it('handles empty values correctly and shows no badges', () => {
        const emptyValuesProps = {
            ...defaultProps,
            values: {
                [FilterKey.policyV2]: [],
                [FilterKey.policyV2Namespace]: [],
                [FilterKey.policyV2Tier]: [],
                [FilterKey.policyV2Kind]: [],
                // Add other required FilterKey properties with empty arrays
                [FilterKey.policy]: [],
                [FilterKey.source_name]: [],
                [FilterKey.source_namespace]: [],
                [FilterKey.dest_name]: [],
                [FilterKey.dest_namespace]: [],
                [FilterKey.start_time]: [],
                [FilterKey.action]: [],
                [FilterKey.dest_port]: [],
                [FilterKey.protocol]: [],
                [FilterKey.reporter]: [],
                [FilterKey.staged_action]: [],
                [FilterKey.pending_action]: [],
            } as Record<FilterKey, string[]>,
        };

        render(<FilterTabs {...emptyValuesProps} />);

        // All tabs should be rendered using role queries
        expect(
            screen.getByRole('tab', { name: 'Policy V2' }),
        ).toBeInTheDocument();
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
        expect(screen.getByTestId('policyV2-selected-count')).toHaveTextContent(
            '0',
        );
    });
});
