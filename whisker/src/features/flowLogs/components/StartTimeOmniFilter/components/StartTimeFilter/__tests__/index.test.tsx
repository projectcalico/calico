import { render, screen, userEvent, waitFor } from '@/test-utils/helper';
import StartTimeFilter from '..';

jest.mock(
    '@/libs/tigera/ui-components/components/common/Select',
    () =>
        ({ options, onChange }: any) => {
            return <div onClick={() => onChange(options[2])}>Mock Select</div>;
        },
);

describe('<StartTimeFilter />', () => {
    const mockOnChange = jest.fn();
    const mockOnClick = jest.fn();
    const mockOnReset = jest.fn();
    const mockOnSubmit = jest.fn();

    const options = [
        { label: 'Last 1 hour', value: '1h' },
        { label: 'Last 6 hours', value: '6h' },
        { label: 'Last 24 hours', value: '24h' },
    ];

    const defaultProps = {
        filterLabel: 'Start Time',
        triggerLabel: 'Last 1 hour',
        value: { label: 'Last 1 hour', value: '1h' },
        isActive: true,
        options,
        hasChanged: false,
        onChange: mockOnChange,
        onClick: mockOnClick,
        onReset: mockOnReset,
        onSubmit: mockOnSubmit,
    };

    beforeEach(() => {
        jest.clearAllMocks();
    });

    const openFilter = async () =>
        await userEvent.click(
            screen.getByRole('button', { name: 'Start Time = Last 1 hour' }),
        );

    it('should call onClick when trigger is clicked', async () => {
        render(<StartTimeFilter {...defaultProps} />);

        await openFilter();

        expect(mockOnClick).toHaveBeenCalled();
    });

    it('should submit the changed value', async () => {
        render(<StartTimeFilter {...defaultProps} />);
        await openFilter();

        // trigger mock event
        await userEvent.click(screen.getByText('Mock Select'));
        expect(mockOnChange).toHaveBeenCalledWith(options[2]);

        await waitFor(() => {
            expect(
                screen.queryByTestId('start-time-popover-body'),
            ).not.toBeInTheDocument();
        });
    });

    it('should call onClear and close popover when clear button is clicked', async () => {
        render(<StartTimeFilter {...defaultProps} hasChanged={true} />);

        await openFilter();
        await userEvent.click(
            screen.getByRole('button', { name: 'Reset filter' }),
        );

        expect(mockOnReset).toHaveBeenCalledTimes(1);
    });
});
