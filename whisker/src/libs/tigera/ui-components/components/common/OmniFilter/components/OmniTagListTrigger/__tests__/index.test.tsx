import { render, screen } from '@testing-library/react';
import OmniTagListTrigger from '..';
import userEvent from '@testing-library/user-event';
import { Popover } from '@chakra-ui/react';

describe('<OmniTagListTrigger />', () => {
    it('should call onOpen', async () => {
        const onOpen = jest.fn();
        render(
            <Popover>
                <OmniTagListTrigger
                    options={[]}
                    onRemove={() => {}}
                    onOpen={onOpen}
                />
            </Popover>,
        );

        await userEvent.click(screen.getByText('Select...'));

        expect(onOpen).toHaveBeenCalled();
    });

    it('should render the tags', async () => {
        const onOpen = jest.fn();
        render(
            <Popover>
                <OmniTagListTrigger
                    options={[
                        { label: 'Tag 1', value: 'tag-1' },
                        { label: 'Tag 2', value: 'tag-2' },
                        { label: 'Tag 3', value: 'tag-3' },
                    ]}
                    onRemove={() => {}}
                    onOpen={onOpen}
                />
            </Popover>,
        );

        expect(screen.getByText('Tag 1')).toBeInTheDocument();
        expect(screen.getByText('Tag 2')).toBeInTheDocument();
        expect(screen.getByText('Tag 3')).toBeInTheDocument();
    });
});
