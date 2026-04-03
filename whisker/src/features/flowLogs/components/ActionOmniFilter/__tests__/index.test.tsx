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
            },
        };

        render(<ActionOmniFilter {...propsWithValues} onChange={onChange} />);

        await openPopover(user);
        await user.click(screen.getByRole('button', { name: 'Clear' }));

        expect(onChange).toHaveBeenCalledWith({
            action: undefined,
            staged_action: undefined,
        });
    });

    it('should initialize with provided values', async () => {
        const user = userEvent.setup();
        const propsWithValues = {
            ...defaultProps,
            value: {
                action: 'Deny',
                staged_action: 'Allow',
            },
        };

        render(<ActionOmniFilter {...propsWithValues} />);

        await openPopover(user);

        const actionToggle = screen.getByTestId('radio-toggle-action');
        const stagedActionToggle = screen.getByTestId(
            'radio-toggle-staged_action',
        );

        expect(actionToggle).toBeInTheDocument();
        expect(stagedActionToggle).toBeInTheDocument();
    });

    it('should not show filter count badge when no filters are active', () => {
        render(<ActionOmniFilter {...defaultProps} />);

        expect(
            screen.getByRole('button', { name: 'Action' }),
        ).toBeInTheDocument();
        expect(screen.queryByText('+0')).not.toBeInTheDocument();
    });

    it('should clear individual action filter via the clear button', async () => {
        const user = userEvent.setup();
        const onChange = jest.fn();

        const propsWithValues = {
            ...defaultProps,
            onChange,
            value: {
                action: 'Allow',
                staged_action: undefined,
            },
        };

        render(<ActionOmniFilter {...propsWithValues} />);

        await openPopover(user);

        await user.click(screen.getByRole('button', { name: 'Clear Action' }));
        await user.click(screen.getByRole('button', { name: 'Update' }));

        expect(onChange).toHaveBeenCalledWith({
            action: '',
            staged_action: '',
        });
    });

    it('should clear individual staged action filter via the clear button', async () => {
        const user = userEvent.setup();
        const onChange = jest.fn();

        const propsWithValues = {
            ...defaultProps,
            onChange,
            value: {
                action: undefined,
                staged_action: 'Deny',
            },
        };

        render(<ActionOmniFilter {...propsWithValues} />);

        await openPopover(user);

        await user.click(
            screen.getByRole('button', { name: 'Clear Staged Action' }),
        );
        await user.click(screen.getByRole('button', { name: 'Update' }));

        expect(onChange).toHaveBeenCalledWith({
            action: '',
            staged_action: '',
        });
    });

    it('should handle staged action toggle changes', async () => {
        const user = userEvent.setup();
        const onChange = jest.fn();

        render(<ActionOmniFilter {...defaultProps} onChange={onChange} />);

        await openPopover(user);

        const stagedToggle = within(
            screen.getByTestId('radio-toggle-staged_action'),
        );
        await user.click(stagedToggle.getByTestId('option-Deny'));

        await user.click(screen.getByRole('button', { name: 'Update' }));

        expect(onChange).toHaveBeenCalledWith({
            action: '',
            staged_action: 'Deny',
        });
    });

    it('should close the popover after submitting', async () => {
        const user = userEvent.setup();
        const onChange = jest.fn();

        render(<ActionOmniFilter {...defaultProps} onChange={onChange} />);

        await openPopover(user);
        expect(screen.getByTestId('action-omni-filter-content')).toBeVisible();

        await user.click(screen.getByRole('button', { name: 'Update' }));

        await waitFor(() => {
            expect(
                screen.getByTestId('action-omni-filter-content'),
            ).not.toBeVisible();
        });
    });

    it('should close the popover after clearing all filters', async () => {
        const user = userEvent.setup();
        const onChange = jest.fn();

        const propsWithValues = {
            ...defaultProps,
            onChange,
            value: {
                action: 'Allow',
                staged_action: undefined,
            },
        };

        render(<ActionOmniFilter {...propsWithValues} />);

        await openPopover(user);
        await user.click(screen.getByRole('button', { name: 'Clear' }));

        await waitFor(() => {
            expect(
                screen.getByTestId('action-omni-filter-content'),
            ).not.toBeVisible();
        });
    });
});
