import { render, screen, userEvent } from '@/test-utils/helper';
import NoPolicyCheckbox from '..';

describe('<NoPolicyCheckbox />', () => {
    const defaultProps = {
        value: false,
        onChange: jest.fn(),
    };

    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('renders the checkbox with label and description', () => {
        render(<NoPolicyCheckbox {...defaultProps} />);

        expect(screen.getByRole('checkbox')).toBeInTheDocument();
        expect(screen.getByText(/No Policy/)).toBeInTheDocument();
        expect(
            screen.getByText(/This filter will clear all existing queries\./),
        ).toBeInTheDocument();
    });

    it('renders unchecked when value is false', () => {
        render(<NoPolicyCheckbox {...defaultProps} value={false} />);

        expect(screen.getByRole('checkbox')).not.toBeChecked();
    });

    it('renders checked when value is true', () => {
        render(<NoPolicyCheckbox {...defaultProps} value={true} />);

        expect(screen.getByRole('checkbox')).toBeChecked();
    });

    it('calls onChange when the checkbox is clicked', async () => {
        render(<NoPolicyCheckbox {...defaultProps} />);

        await userEvent.click(screen.getByRole('checkbox'));

        expect(defaultProps.onChange).toHaveBeenCalledWith(true);
    });

    it('calls onChange with false when unchecking', async () => {
        render(<NoPolicyCheckbox {...defaultProps} value={true} />);

        await userEvent.click(screen.getByRole('checkbox'));

        expect(defaultProps.onChange).toHaveBeenCalledWith(false);
    });
});
