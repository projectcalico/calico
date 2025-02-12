import { fireEvent, render, screen } from '@/test-utils/helper';
import OmniFilters from '..';

jest.mock(
    '@/libs/tigera/ui-components/components/common/OmniFilter',
    () =>
        ({ filterLabel, onClear }: any) => {
            return <div onClick={onClear}>{filterLabel}</div>;
        },
);

describe('<OmniFilters />', () => {
    it('should clear the filter', () => {
        const mockOnChange = jest.fn();
        render(
            <OmniFilters
                onChange={mockOnChange}
                onReset={jest.fn()}
                selectedFilters={{} as any}
            />,
        );

        fireEvent.click(screen.getByText('Policy'));

        expect(mockOnChange).toHaveBeenCalledWith({
            filterId: 'policy',
            filterLabel: '',
            filters: [],
            operator: undefined,
        });
    });
});
