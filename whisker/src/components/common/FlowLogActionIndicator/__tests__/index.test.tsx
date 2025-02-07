import { render } from '@/test-utils/helper';
import FlowLogActionIndicator from '..';

describe('FlowLogActionIndicator', () => {
    it('should match the snapshot', () => {
        const { asFragment } = render(<FlowLogActionIndicator action='log' />);

        expect(asFragment()).toMatchSnapshot();
    });
});
