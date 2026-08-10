import { fireEvent, render, screen } from '@/test-utils/helper';
import { OmniFilterContainer } from '@/libs/tigera/ui-components/components/common/OmniFilter/parts';
import FilterFooter from '..';

// OmniFilterFooter reads the OmniFilter styles context and the popover
// styles context, both provided by OmniFilterContainer.
const renderFooter = (props: React.ComponentProps<typeof FilterFooter>) =>
    render(
        <OmniFilterContainer>
            <FilterFooter {...props} />
        </OmniFilterContainer>,
    );

describe('<FilterFooter />', () => {
    it('should render an empty footer when no button props are given', () => {
        renderFooter({ testId: 'my-filter' });

        const footer = screen.getByTestId('my-filter-popover-footer');
        expect(footer).toBeInTheDocument();
        expect(footer.querySelector('button')).toBeNull();
    });

    it('should fall back to the Clear and Update labels', () => {
        const onClear = jest.fn();
        const onUpdate = jest.fn();
        renderFooter({
            testId: 'my-filter',
            leftButtonProps: { onClick: onClear },
            rightButtonProps: { onClick: onUpdate },
        });

        fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
        expect(onClear).toHaveBeenCalled();

        fireEvent.click(screen.getByRole('button', { name: 'Update' }));
        expect(onUpdate).toHaveBeenCalled();
    });

    it('should render custom button labels when provided', () => {
        renderFooter({
            testId: 'my-filter',
            leftButtonProps: { children: 'Reset filter' },
            rightButtonProps: { children: 'Apply' },
        });

        expect(
            screen.getByRole('button', { name: 'Reset filter' }),
        ).toBeInTheDocument();
        expect(
            screen.getByRole('button', { name: 'Apply' }),
        ).toBeInTheDocument();
        expect(screen.queryByText('Clear')).not.toBeInTheDocument();
        expect(screen.queryByText('Update')).not.toBeInTheDocument();
    });

    it('should render only the right button when the left is omitted', () => {
        renderFooter({
            testId: 'my-filter',
            rightButtonProps: { children: 'Apply' },
        });

        const footer = screen.getByTestId('my-filter-popover-footer');
        expect(footer.querySelectorAll('button')).toHaveLength(1);
        expect(
            screen.getByRole('button', { name: 'Apply' }),
        ).toBeInTheDocument();
    });
});
