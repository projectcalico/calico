import { render, screen, fireEvent, waitFor } from '@/test-utils/helper';
import userEvent from '@testing-library/user-event';
import OmniFilterList from '..';
import OmniFilter from '../../OmniFilter';

describe('OmniFilterList component', () => {
    const defaultFilterIds = ['example1', 'example2'];
    const visibleFilterIds = ['example1', 'example2'];

    it('calls onResetVisible when reset button is clicked', () => {
        const onResetVisible = jest.fn();
        render(
            <OmniFilterList
                defaultFilterIds={defaultFilterIds}
                visibleFilterIds={visibleFilterIds}
                onResetVisible={onResetVisible}
                onChangeVisible={jest.fn()}
            >
                <OmniFilter
                    filterId='example1'
                    filterLabel='Example 1'
                    filters={[
                        { label: 'Option 1', value: '1' },
                        { label: 'Option 2', value: '2' },
                    ]}
                    selectedFilters={[{ label: 'Option 1', value: '1' }]}
                    onChange={jest.fn()}
                    onClear={jest.fn()}
                />
                <OmniFilter
                    filterId='example2'
                    filterLabel='Example 2'
                    filters={[{ label: 'Item 1', value: '1' }]}
                    selectedFilters={[]}
                    onChange={jest.fn()}
                    onClear={jest.fn()}
                />
            </OmniFilterList>,
        );

        expect(screen.getByText('Example 1')).toBeInTheDocument();
        expect(screen.getByText('Example 2')).toBeInTheDocument();
        expect(screen.queryByText('More +')).toBeNull();

        const resetButton = screen.getByTestId('omnifilterlist-reset');
        fireEvent.click(resetButton);
        expect(onResetVisible).toHaveBeenCalled();
    });

    it('handles more filters correctly', async () => {
        const newVisibleFilterIds = [...visibleFilterIds, 'example3'];
        const onChangeVisible = jest.fn();
        render(
            <OmniFilterList
                defaultFilterIds={defaultFilterIds}
                visibleFilterIds={newVisibleFilterIds}
                onResetVisible={jest.fn()}
                onChangeVisible={onChangeVisible}
            >
                <OmniFilter
                    filterId='example1'
                    filterLabel='Example 1'
                    filters={[
                        { label: 'Option 1', value: '1' },
                        { label: 'Option 2', value: '2' },
                    ]}
                    selectedFilters={[{ label: 'Option 1', value: '1' }]}
                    onChange={jest.fn()}
                    onClear={jest.fn()}
                />
                <OmniFilter
                    filterId='example2'
                    filterLabel='Example 2'
                    filters={[{ label: 'Item 1', value: '1' }]}
                    selectedFilters={[]}
                    onChange={jest.fn()}
                    onClear={jest.fn()}
                />
                <OmniFilter
                    filterId='example3'
                    filterLabel='Example 3'
                    filters={[
                        { label: 'Sheep', value: '1' },
                        { label: 'Car', value: '2' },
                    ]}
                    selectedFilters={[]}
                    onChange={jest.fn()}
                    onClear={jest.fn()}
                />
            </OmniFilterList>,
        );
        expect(screen.getByText('More +')).toBeInTheDocument();
        fireEvent.click(screen.getByText('More +'));

        const checkbox: any = document.querySelector('.chakra-checkbox');
        expect(checkbox).toBeInTheDocument();
        userEvent.click(checkbox);

        await waitFor(() => {
            expect(onChangeVisible).toHaveBeenCalledWith(visibleFilterIds);
        });
    });
});
