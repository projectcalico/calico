import { render } from '@/test-utils/helper';
import Tag from '../index';

describe('<Tag/>', () => {
    it('it renders', () => {
        const { asFragment } = render(<Tag>Hola active tag!</Tag>);

        expect(asFragment()).toMatchSnapshot();
    });

    it('it renders inactive', () => {
        const { asFragment } = render(
            <Tag isActive={false}>Hola inactive tag!</Tag>,
        );

        expect(asFragment()).toMatchSnapshot();
    });
});
