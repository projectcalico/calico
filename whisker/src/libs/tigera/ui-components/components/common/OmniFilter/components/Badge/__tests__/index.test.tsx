import { render, screen } from '@testing-library/react';
import Badge from '..';

describe('<Badge />', () => {
    it('should render the badge', () => {
        render(<Badge>4</Badge>);

        expect(screen.getByText('+4')).toBeInTheDocument();
    });
});
