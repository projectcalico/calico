import ReorderableCheckList from '..';
import { render, screen, fireEvent } from '@/test-utils/helper';

const mockOnsave = jest.fn();
const mockOnClose = jest.fn();

const defaultProps = {
    onSave: mockOnsave,
    onClose: mockOnClose,
    title: 'Column Customizer',
    items: [
        { id: 'item 1' },
        { id: 'item 2' },
        { id: 'item 3' },
        { id: 'item 4' },
    ],

    isOpen: true,
} as any;

describe('ReorderableCheckList', () => {
    it('should render', () => {
        render(<ReorderableCheckList {...defaultProps} />);
        expect(screen.getByText('Column Customizer')).toBeInTheDocument();
        expect(screen.getByText('item 1')).toBeInTheDocument();
    });

    it('should be able to select/deselect item', () => {
        render(<ReorderableCheckList {...defaultProps} />);
        fireEvent.click(screen.getByText('item 1'));
        fireEvent.click(screen.getByText('Save'));
        expect(mockOnsave).toHaveBeenCalled();
    });

    it('should call OnClose', () => {
        render(<ReorderableCheckList {...defaultProps} />);
        fireEvent.click(screen.getByText('Cancel'));
        expect(mockOnClose).toHaveBeenCalled();
    });
});
