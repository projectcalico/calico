import { render } from '@/test-utils/helper';
import StatusIndicator from '../index';

describe('<StatusIndicator/>', () => {
    it('it renders', () => {
        const { asFragment } = render(
            <StatusIndicator color={'#f00'} label='foo' />,
        );
        expect(asFragment()).toMatchSnapshot();
    });
});
