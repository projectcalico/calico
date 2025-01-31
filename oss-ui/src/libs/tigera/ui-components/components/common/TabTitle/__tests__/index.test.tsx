import { render } from '@/test-utils/helper';
import TabTitle from '..';

const defaultProps = {
    isSelected: true,
    hasNoData: false,
    badgeCount: 10,
    title: 'some title',
} as any;

describe('<TabTitle', () => {
    it('renders TabTitle -- happy path', () => {
        const { asFragment } = render(<TabTitle {...defaultProps} />);

        expect(asFragment()).toMatchSnapshot();
    });

    it('renders TabTitle -- alt path when has no data', () => {
        const { asFragment } = render(
            <TabTitle {...defaultProps} hasNoData={true} isSelected={false} />,
        );

        expect(asFragment()).toMatchSnapshot();
    });

    it('renders TabTitle -- alt path when not selected', () => {
        const { asFragment } = render(
            <TabTitle {...defaultProps} hasNoData={false} isSelected={false} />,
        );

        expect(asFragment()).toMatchSnapshot();
    });
});
