import { render, screen, userEvent } from '@/test-utils/helper';
import RadioToggleGroup from '..';

const mockOptions = [
    { value: 'option1', label: 'Option 1' },
    {
        value: 'option2',
        label: 'Option 2',
        icon: <span data-testid='icon'>🎯</span>,
    },
    { value: 'option3', label: 'Option 3' },
];

const defaultProps = {
    name: 'test-radio',
    value: undefined,
    onChange: jest.fn(),
    options: mockOptions,
};

describe('RadioToggleGroup', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should render all options', () => {
        render(<RadioToggleGroup {...defaultProps} />);

        expect(screen.getByText('Option 1')).toBeInTheDocument();
        expect(screen.getByText('Option 2')).toBeInTheDocument();
        expect(screen.getByText('Option 3')).toBeInTheDocument();
    });

    it('should render icons when provided', () => {
        render(<RadioToggleGroup {...defaultProps} />);

        expect(screen.getByTestId('icon')).toBeInTheDocument();
    });

    it('should call onChange when option is clicked', async () => {
        const user = userEvent.setup();
        const onChange = jest.fn();

        render(<RadioToggleGroup {...defaultProps} onChange={onChange} />);

        await user.click(screen.getByText('Option 1'));
        expect(onChange).toHaveBeenCalledWith('option1');
        expect(screen.getByDisplayValue('option1')).toBeChecked();
    });

    it('should clear the value', async () => {
        const user = userEvent.setup();
        const onChange = jest.fn();

        render(
            <RadioToggleGroup
                {...defaultProps}
                value='option1'
                onChange={onChange}
            />,
        );

        await user.click(screen.getByText('Option 1'));
        expect(onChange).toHaveBeenCalledWith('');
    });
});
