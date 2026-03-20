import { render, screen } from '@/test-utils/helper';
import userEvent from '@testing-library/user-event';
import ClearableFormLabel from '../index';

describe('<ClearableFormLabel />', () => {
    const defaultProps = {
        children: 'Test Label',
        showClearButton: false,
        onClear: jest.fn(),
        clearButtonAriaLabel: 'Clear test',
    };

    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('renders the label with children and does not show clear button when showClearButton is false', () => {
        render(<ClearableFormLabel {...defaultProps} />);

        expect(screen.getByText('Test Label')).toBeInTheDocument();
        expect(screen.queryByRole('button')).not.toBeInTheDocument();
    });

    it('does not render the clear button when showClearButton is undefined', () => {
        render(
            <ClearableFormLabel
                {...defaultProps}
                showClearButton={undefined as any}
            />,
        );

        expect(screen.getByText('Test Label')).toBeInTheDocument();
        expect(screen.queryByRole('button')).not.toBeInTheDocument();
    });

    it('calls onClear when the clear button is clicked', async () => {
        const user = userEvent.setup();
        const onClearMock = jest.fn();

        render(
            <ClearableFormLabel
                {...defaultProps}
                showClearButton={true}
                onClear={onClearMock}
            />,
        );

        const clearButton = screen.getByRole('button', {
            name: /clear test/i,
        });
        await user.click(clearButton);

        expect(onClearMock).toHaveBeenCalledTimes(1);
    });
});
