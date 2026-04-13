import { fireEvent, render, screen } from '@/test-utils/helper';
import SelectListItem from '..';

const option = { label: 'NetworkPolicy', value: 'NetworkPolicy' };

describe('<SelectListItem />', () => {
    it('renders the label and a check icon when selected', () => {
        render(
            <SelectListItem
                isSelected={true}
                option={option}
                index={0}
                onSelect={jest.fn()}
            />,
        );

        expect(screen.getByText('NetworkPolicy')).toBeInTheDocument();
        expect(
            screen.getByTestId('select-list-item-check-icon'),
        ).toBeInTheDocument();
    });

    it('hides the check icon when not selected and calls onSelect on click', () => {
        const onSelect = jest.fn();
        render(
            <SelectListItem
                isSelected={false}
                option={option}
                index={0}
                onSelect={onSelect}
            />,
        );

        expect(
            screen.queryByTestId('select-list-item-check-icon'),
        ).not.toBeInTheDocument();

        fireEvent.click(screen.getByText('NetworkPolicy'));

        expect(onSelect).toHaveBeenCalledTimes(1);
    });
});
