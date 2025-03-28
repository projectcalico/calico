import { MenuItem } from '@chakra-ui/react';
import { fireEvent, render, screen } from '@/test-utils/helper';
import ActionMenu from '../index';

describe('<ActionMenu/>', () => {
    it('it renders', () => {
        const { asFragment } = render(
            <ActionMenu buttonValue='mockValue' buttonAriaLabel='="mockAria'>
                <MenuItem>Example</MenuItem>
            </ActionMenu>,
        );

        fireEvent.click(screen.getByTestId('action-menu-button'));

        expect(asFragment()).toMatchSnapshot();
    });
});
