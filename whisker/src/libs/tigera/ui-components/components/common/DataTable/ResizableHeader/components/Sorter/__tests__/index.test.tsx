import { render } from '@/test-utils/helper';
import Sorter from '../index';

describe('<Sorter/>', () => {
    it('it renders descending', () => {
        const { asFragment } = render(
            <Sorter isActive={true} isDescending={true} />,
        );

        expect(asFragment()).toMatchSnapshot();
    });

    it('it renders ascending', () => {
        const { asFragment } = render(
            <Sorter isActive={true} isDescending={false} />,
        );

        expect(asFragment()).toMatchSnapshot();
    });

    it('it renders inactive', () => {
        const { asFragment } = render(
            <Sorter isActive={false} isDescending={false} />,
        );

        expect(asFragment()).toMatchSnapshot();
    });
});
