import { act, render, screen, userEvent } from '@/test-utils/helper';
import PolicyOmniFilter from '..';

const MockTagListOmniFilter: any = {};

jest.mock('../FilterTabs', () => ({ onChange, filterId, onClear }: any) => {
    if (filterId === 'policy') {
        MockTagListOmniFilter[filterId] = { onChange, onClear };
    }
    return <div>FilterTabs - {filterId}</div>;
});

describe('<PolicyOmniFilter />', () => {
    const defaultProps = {
        onChange: jest.fn(),
        selectedValues: {},
        filterLabel: '',
        filterId: '',
        filterQuery: {},
        selectedFilters: [],
    } as any;

    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should submmit the filter values', async () => {
        render(<PolicyOmniFilter {...defaultProps} />);

        await userEvent.click(screen.getByRole('button', { name: 'Policy' }));

        act(() =>
            MockTagListOmniFilter.policy.onChange({
                filterId: 'policy',
                filters: [{ value: 'filter-value' }],
            }),
        );

        await userEvent.click(screen.getByRole('button', { name: 'Update' }));

        expect(defaultProps.onChange).toHaveBeenCalledWith({
            policy: ['filter-value'],
        });
    });

    it('should clear the values', async () => {
        render(<PolicyOmniFilter {...defaultProps} />);

        await userEvent.click(screen.getByRole('button', { name: 'Policy' }));

        act(() =>
            MockTagListOmniFilter.policy.onChange({
                filterId: 'policy',
                filters: [{ value: 'filter-value' }],
            }),
        );

        await userEvent.click(screen.getByRole('button', { name: 'Update' }));

        expect(defaultProps.onChange).toHaveBeenCalledWith({
            policy: ['filter-value'],
        });
    });

    it('should clear a filter and sumbit the values', async () => {
        render(
            <PolicyOmniFilter
                {...defaultProps}
                selectedValues={{
                    policy: ['policy-value'],
                    policyNamespace: ['namespace-value'],
                    policyTier: ['tier-value'],
                    policyKind: ['kind-value'],
                }}
            />,
        );

        await userEvent.click(
            screen.getByRole('button', { name: 'Policy +4' }),
        );

        act(() => MockTagListOmniFilter.policy.onClear('policy'));

        await userEvent.click(screen.getByRole('button', { name: 'Update' }));

        expect(defaultProps.onChange).toHaveBeenCalledWith({
            policy: [],
            policyNamespace: ['namespace-value'],
            policyTier: ['tier-value'],
            policyKind: ['kind-value'],
        });
    });

    it('should clear all values', async () => {
        render(
            <PolicyOmniFilter
                {...defaultProps}
                selectedValues={{
                    policy: ['policy-value'],
                    policyNamespace: ['namespace-value'],
                    policyTier: ['tier-value'],
                    policyKind: ['kind-value'],
                }}
            />,
        );

        await userEvent.click(
            screen.getByRole('button', { name: 'Policy +4' }),
        );

        await userEvent.click(
            screen.getByRole('button', { name: 'Clear all' }),
        );

        expect(defaultProps.onChange).toHaveBeenCalledWith({
            policy: [],
            policyNamespace: [],
            policyTier: [],
            policyKind: [],
        });
    });
});
