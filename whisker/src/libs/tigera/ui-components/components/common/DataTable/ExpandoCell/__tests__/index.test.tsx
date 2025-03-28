import { render } from '@/test-utils/helper';
import ExpandoCell from '../index';

describe('<ExpandoCell/>', () => {
    it('it renders', () => {
        const { asFragment } = render(
            <ExpandoCell isExpanded={false} value='Some Cell Value' />,
        );
        expect(asFragment()).toMatchSnapshot();
    });

    it('it renders inactive', () => {
        const { asFragment } = render(
            <ExpandoCell isExpanded={true} value='Some Cell Value' />,
        );

        expect(asFragment()).toMatchSnapshot();
    });
});
