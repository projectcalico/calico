import { render, screen } from '@/test-utils/helper';
import PolicyActionIndicator from '..';

describe('PolicyActionIndicator', () => {
    it('renders the action text', () => {
        render(<PolicyActionIndicator action='Allow' />);
        expect(screen.getByText('Allow')).toBeInTheDocument();
    });

    it('falls back to "Unspecified" when action is null', () => {
        render(<PolicyActionIndicator action={null} />);
        expect(screen.getByText('Unspecified')).toBeInTheDocument();
    });
});
