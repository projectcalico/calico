import { renderWithRouter, screen } from '@/test-utils/helper';
import AppHeader from '..';

jest.mock('@/hooks', () => ({
    useClusterId: jest.fn().mockReturnValue('fake-cluster-id'),
}));

describe('<AppHeader />', () => {
    it('should add the whisker id to the calico cloud link', () => {
        renderWithRouter(<AppHeader />);

        expect(
            screen.getByTestId('app-header-calico-cloud-link'),
        ).toHaveProperty(
            'href',
            expect.stringContaining(`whisker_id=fake-cluster-id`),
        );
    });
});
