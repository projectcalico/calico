import { render, screen, fireEvent } from '@testing-library/react';
import Tag from '../index';

describe('Tag', () => {
    const mockTag = {
        value: 'test-value',
        label: 'Test Label',
    };

    const mockOnRemove = jest.fn();

    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should display the correct tag label', () => {
        render(<Tag tag={mockTag} onRemove={mockOnRemove} />);

        expect(screen.getByText('Test Label')).toBeInTheDocument();
    });

    it('should call onRemove when close button is clicked', () => {
        render(<Tag tag={mockTag} onRemove={mockOnRemove} />);

        const closeButton = screen.getByTestId('tag-close-button');
        fireEvent.click(closeButton);

        expect(mockOnRemove).toHaveBeenCalledTimes(1);
        expect(mockOnRemove).toHaveBeenCalledWith(mockTag);
    });
});
