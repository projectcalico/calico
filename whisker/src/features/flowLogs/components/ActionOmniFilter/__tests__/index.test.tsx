import {
    render,
    screen,
    userEvent,
    waitFor,
    within,
} from '@/test-utils/helper';
import ActionOmniFilter from '..';

// Mock RadioToggle component
jest.mock('@/components/common/RadioToggle', () => {
    return function MockRadioToggle({
        value,
        onChange,
        options,
        testId,
    }: {
        name: string;
        value: string;
        onChange: (value: string) => void;
        options: Array<{ value: string; label: string }>;
        testId: string;
    }) {
        return (
            <div data-testid={testId}>
                {options.map((option) => (
                    <button
                        key={option.value}
                        data-testid={`option-${option.value}`}
                        onClick={() => onChange(option.value)}
                        style={{
                            backgroundColor:
                                value === option.value ? 'blue' : 'white',
                        }}
                    >
                        {option.label}
                    </button>
                ))}
            </div>
        );
    };
});

const defaultProps = {
    onChange: jest.fn(),
    selectedFilters: [],
    filterLabel: 'Action',
    filterId: 'action' as any,
    value: {
        action: undefined,
        staged_action: undefined,
        pending_action: undefined,
    },
};

describe('ActionOmniFilter', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    const openPopover = async (user: any) =>
        await user.click(screen.getByText('Action'));

    it('should show filter count badge when filters are active', () => {
        const propsWithValues = {
            ...defaultProps,
            value: {
                action: 'Allow',
                staged_action: 'Deny',
                pending_action: undefined,
            },
        };

        render(<ActionOmniFilter {...propsWithValues} />);

        expect(
            screen.getByRole('button', { name: 'Action +2' }),
        ).toBeInTheDocument();
    });

    it('should render action and staged action toggle groups', async () => {
        const user = userEvent.setup();
        render(<ActionOmniFilter {...defaultProps} />);

        await openPopover(user);

        const content = within(
            screen.getByTestId('action-omni-filter-content'),
        );

        expect(content.getByTestId('radio-toggle-action')).toBeInTheDocument();
        expect(
            content.getByTestId('radio-toggle-staged_action'),
        ).toBeInTheDocument();
        expect(content.getByText('Action')).toBeInTheDocument();
        expect(content.getByText('Staged Action')).toBeInTheDocument();
    });

    it('should render pending action radio toggle group when more filters is clicked', async () => {
        const user = userEvent.setup();
        render(<ActionOmniFilter {...defaultProps} />);

        await openPopover(user);

        window.scrollTo = jest.fn();
        expect(screen.getByText('Pending Action')).not.toBeVisible();

        await user.click(screen.getByRole('button', { name: 'More filters' }));

        await waitFor(() => {
            expect(screen.queryByText('Pending Action')).toBeVisible();
        });
    });

    it('should handle radio toggle changes', async () => {
        const user = userEvent.setup();
        const onChange = jest.fn();

        render(<ActionOmniFilter {...defaultProps} onChange={onChange} />);

        await openPopover(user);

        const actionToggle = within(screen.getByTestId('radio-toggle-action'));
        await user.click(actionToggle.getByTestId('option-Allow'));

        // Click submit to trigger onChange
        await user.click(screen.getByRole('button', { name: 'Update' }));

        expect(onChange).toHaveBeenCalledWith({
            action: 'Allow',
            staged_action: '',
            pending_action: '',
        });
    });

    it('should clear all filters when clear button is clicked', async () => {
        const user = userEvent.setup();
        const onChange = jest.fn();

        const propsWithValues = {
            ...defaultProps,
            value: {
                action: 'Allow',
                staged_action: 'Deny',
                pending_action: 'Allow',
            },
        };

        render(<ActionOmniFilter {...propsWithValues} onChange={onChange} />);

        await openPopover(user);
        await user.click(screen.getByRole('button', { name: 'Clear' }));

        expect(onChange).toHaveBeenCalledWith({
            action: undefined,
            staged_action: undefined,
            pending_action: undefined,
        });
    });

    it('should expand accordion when pending action has value', async () => {
        const user = userEvent.setup();
        const propsWithPendingAction = {
            ...defaultProps,
            value: {
                action: undefined,
                staged_action: undefined,
                pending_action: 'Allow',
            },
        };

        render(<ActionOmniFilter {...propsWithPendingAction} />);

        await openPopover(user);

        expect(
            await screen.findByTestId('radio-toggle-pending_action'),
        ).toBeInTheDocument();
    });

    it('should initialize with provided values', async () => {
        const user = userEvent.setup();
        const propsWithValues = {
            ...defaultProps,
            value: {
                action: 'Deny',
                staged_action: 'Allow',
                pending_action: 'Deny',
            },
        };

        render(<ActionOmniFilter {...propsWithValues} />);

        await openPopover(user);

        const actionToggle = screen.getByTestId('radio-toggle-action');
        const stagedActionToggle = screen.getByTestId(
            'radio-toggle-staged_action',
        );
        const pendingActionToggle = screen.getByTestId(
            'radio-toggle-pending_action',
        );

        expect(actionToggle).toBeInTheDocument();
        expect(stagedActionToggle).toBeInTheDocument();
        expect(pendingActionToggle).toBeInTheDocument();
    });
});
