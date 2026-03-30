import { render, screen } from '@testing-library/react';
import { Text } from './index';

describe('Text Component', () => {
    it('renders as a paragraph by default', () => {
        render(<Text>Default text</Text>);
        const el = screen.getByText(/default text/i);
        expect(el.tagName).toBe('P');
    });

    it('applies size variant classes', () => {
        render(<Text size='lg'>Large text</Text>);
        const el = screen.getByText(/large text/i);
        expect(el).toHaveClass('text-lg');
    });

    it('applies custom className', () => {
        render(<Text className='custom-class'>Custom text</Text>);
        const el = screen.getByText(/custom text/i);
        expect(el).toHaveClass('custom-class');
    });
});
