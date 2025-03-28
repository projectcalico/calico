import { renderWithRouter } from '@/test-utils/helper';
import Link from '../index';

describe('<Link/>', () => {
    it('it renders with to (internal url)', () => {
        const { asFragment } = renderWithRouter(<Link to='/test' />);

        expect(asFragment()).toMatchSnapshot();
    });

    it('it renders with href', () => {
        const { asFragment } = renderWithRouter(
            <Link href='http://tigera.io/' />,
        );

        expect(asFragment()).toMatchSnapshot();
    });
});
