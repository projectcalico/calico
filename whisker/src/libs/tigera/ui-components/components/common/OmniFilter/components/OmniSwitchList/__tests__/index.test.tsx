import { fireEvent, render, screen } from '@/test-utils/helper';
import OmniSwitchList from '../index';

const options = [{ label: 'Switch', value: 'true' }];

const onChange = jest.fn();

const defaultProps = {
    emptyMessage: '',
    showMoreButton: false,
    isLoadingMore: false,
};

describe('OmniSwitchList Component', () => {
    it('should toggle the switch and call onChange with filter values', () => {
        const [option] = options;

        render(
            <OmniSwitchList
                {...defaultProps}
                options={options}
                selectedOptions={[]}
                onChange={onChange}
            />,
        );

        fireEvent.click(screen.getByLabelText(option.label));

        expect(onChange).toHaveBeenCalledWith(options);
    });

    it('should toggle the checked switch and call onChange with updated values', () => {
        const [option] = options;

        render(
            <OmniSwitchList
                {...defaultProps}
                options={options}
                selectedOptions={options}
                onChange={onChange}
            />,
        );

        fireEvent.click(screen.getByLabelText(option.label));

        expect(onChange).toHaveBeenCalledWith([]);
    });
});
