import { render } from '@/test-utils/helper';
import JsonPrettier from '..';

const defaultProps = {
    data: {
        a: 'one',
        b: 2,
        c: null,
        d: undefined,
        e: { f: 'g' },
        x: ['y', 'z'],
    },
};

describe('JsonPrettier', () => {
    it('should render', () => {
        const { asFragment } = render(<JsonPrettier {...defaultProps} />);
        expect(asFragment()).toMatchSnapshot();
    });
});
