import { render } from '@/test-utils/helper';
import TableSkeleton from '../index';

describe('<TableSkeleton/>', () => {
    it('it renders with defaults', () => {
        const { asFragment } = render(<TableSkeleton />);

        expect(asFragment()).toMatchSnapshot();
    });

    it('it renders with values', () => {
        const { asFragment } = render(
            <TableSkeleton stacks={2} skeletonsPerStack={10} />,
        );
        expect(asFragment()).toMatchSnapshot();
    });
});
