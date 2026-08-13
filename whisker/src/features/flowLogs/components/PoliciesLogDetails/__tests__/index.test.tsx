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

    it('transforms Profile policies into default-tier EndOfTier entries', () => {
        const profileData = {
            enforced: [
                makePolicy({
                    kind: 'Profile',
                    namespace: 'profile-ns',
                    name: 'kns.default',
                    tier: 'some-tier',
                    policy_index: 3,
                    rule_index: 4,
                }),
            ],
            pending: [],
        };

        render(<PoliciesLogDetails tableCellData={profileData} />);

        expect(screen.getByText('EndOfTier')).toBeInTheDocument();
        expect(screen.getByText('default')).toBeInTheDocument();
        // the profile name, tier and indices are replaced
        expect(screen.queryByText('kns.default')).not.toBeInTheDocument();
        expect(screen.queryByText('some-tier')).not.toBeInTheDocument();
        expect(screen.queryByText('3')).not.toBeInTheDocument();
        expect(screen.queryByText('4')).not.toBeInTheDocument();
    });

    it('clears policy and rule indexes for EndOfTier policies', () => {
        const endOfTierData = {
            enforced: [
                makePolicy({
                    kind: 'EndOfTier',
                    name: 'end-of-tier-policy',
                    policy_index: 7,
                    rule_index: 8,
                }),
            ],
            pending: [],
        };

        render(<PoliciesLogDetails tableCellData={endOfTierData} />);

        expect(screen.getByText('end-of-tier-policy')).toBeInTheDocument();
        expect(screen.queryByText('7')).not.toBeInTheDocument();
        expect(screen.queryByText('8')).not.toBeInTheDocument();
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

    it('renders trigger without a namespace prefix when the trigger has no namespace', () => {
        const triggeredData = {
            enforced: [
                makePolicy({
                    trigger: {
                        kind: 'GlobalNetworkPolicy',
                        namespace: '',
                        name: 'global-trigger',
                    },
                } as any),
            ],
            pending: [],
        };

        render(<PoliciesLogDetails tableCellData={triggeredData} />);

        // the trigger name is rendered without a namespace prefix
        const [triggerButton] = screen.getAllByText('global-trigger');
        expect(triggerButton).toBeInTheDocument();
        fireEvent.click(triggerButton);
        expect(screen.getByText('GlobalNetworkPolicy')).toBeInTheDocument();
        // no namespace row is rendered in the popover
        expect(
            screen.queryByText('Namespace', { selector: 'td' }),
        ).not.toBeInTheDocument();
    });
});
