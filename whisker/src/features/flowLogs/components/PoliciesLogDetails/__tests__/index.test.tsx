import { render, screen, fireEvent } from '@/test-utils/helper';
import { Policy } from '@/types/api';
import PoliciesLogDetails from '..';

const makePolicy = (overrides: Partial<Policy> = {}): Policy => ({
    kind: 'NetworkPolicy',
    namespace: 'default',
    name: 'test-policy',
    tier: 'default',
    action: 'Allow',
    policy_index: 1,
    rule_index: 2,
    ...overrides,
});

describe('PoliciesLogDetails', () => {
    const baseData = {
        enforced: [makePolicy()],
        pending: [makePolicy({ action: 'Deny', name: 'pending-policy' })],
    };

    it('renders headings and table rows for enforced and pending policies', () => {
        render(<PoliciesLogDetails tableCellData={baseData} />);
        expect(screen.getByText('Enforced Policies')).toBeInTheDocument();
        expect(screen.getByText('Pending Policies')).toBeInTheDocument();
        expect(screen.getByText('test-policy')).toBeInTheDocument();
        expect(screen.getByText('pending-policy')).toBeInTheDocument();
        expect(screen.getByText('Allow')).toBeInTheDocument();
        expect(screen.getByText('Deny')).toBeInTheDocument();
        expect(screen.getAllByText('-')).toHaveLength(2); // one for each policy without trigger
    });

    it('renders trigger info in popover when trigger is provided', () => {
        const triggeredData = {
            enforced: [
                makePolicy({
                    trigger: {
                        kind: 'NetworkPolicyTriggerTest',
                        namespace: 'ns1',
                        name: 'triggered-policy',
                    },
                } as any),
            ],
            pending: [],
        };

        render(<PoliciesLogDetails tableCellData={triggeredData} />);

        expect(screen.getByText('ns1/triggered-policy')).toBeInTheDocument();
        fireEvent.click(screen.getByText('ns1/triggered-policy'));
        expect(
            screen.getByText('NetworkPolicyTriggerTest'),
        ).toBeInTheDocument();
    });
});
