import { act, render, screen, userEvent } from '@/test-utils/helper';
import PolicyOmniFilter from '..';

const MockTagListOmniFilter: any = {};

jest.mock('../FilterTabs', () => ({ onChange, filterId, onClear }: any) => {
    if (filterId === 'policyV2') {
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

        await userEvent.click(
            screen.getByRole('button', { name: 'Policy V2' }),
        );

        act(() =>
            MockTagListOmniFilter.policyV2.onChange({
                filterId: 'policyV2',
                filters: [{ value: 'filter-value' }],
            }),
        );

        await userEvent.click(screen.getByRole('button', { name: 'Update' }));

        expect(defaultProps.onChange).toHaveBeenCalledWith({
            policyV2: ['filter-value'],
        });
    });

    it('should clear the values', async () => {
        render(<PolicyOmniFilter {...defaultProps} />);

        await userEvent.click(
            screen.getByRole('button', { name: 'Policy V2' }),
        );

        act(() =>
            MockTagListOmniFilter.policyV2.onChange({
                filterId: 'policyV2',
                filters: [{ value: 'filter-value' }],
            }),
        );

        await userEvent.click(screen.getByRole('button', { name: 'Update' }));

        expect(defaultProps.onChange).toHaveBeenCalledWith({
            policyV2: ['filter-value'],
        });
    });

    it('should clear a filter and sumbit the values', async () => {
        render(
            <PolicyOmniFilter
                {...defaultProps}
                selectedValues={{
                    policyV2: ['policy-value'],
                    policyV2Namespace: ['namespace-value'],
                    policyV2Tier: ['tier-value'],
                    policyV2Kind: ['kind-value'],
                }}
            />,
        );

        await userEvent.click(
            screen.getByRole('button', { name: 'Policy V2 +4' }),
        );

        act(() => MockTagListOmniFilter.policyV2.onClear('policyV2'));

        await userEvent.click(screen.getByRole('button', { name: 'Update' }));

        expect(defaultProps.onChange).toHaveBeenCalledWith({
            policyV2: [],
            policyV2Namespace: ['namespace-value'],
            policyV2Tier: ['tier-value'],
            policyV2Kind: ['kind-value'],
        });
    });

    it('should clear all values', async () => {
        render(
            <PolicyOmniFilter
                {...defaultProps}
                selectedValues={{
                    policyV2: ['policy-value'],
                    policyV2Namespace: ['namespace-value'],
                    policyV2Tier: ['tier-value'],
                    policyV2Kind: ['kind-value'],
                }}
            />,
        );

        await userEvent.click(
            screen.getByRole('button', { name: 'Policy V2 +4' }),
        );

        await userEvent.click(
            screen.getByRole('button', { name: 'Clear all' }),
        );

        expect(defaultProps.onChange).toHaveBeenCalledWith({
            policyV2: [],
            policyV2Namespace: [],
            policyV2Tier: [],
            policyV2Kind: [],
        });
    });
});
