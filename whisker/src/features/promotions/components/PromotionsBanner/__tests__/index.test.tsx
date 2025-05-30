import { fireEvent, render, screen } from '@/test-utils/helper';
import PromotionsBanner from '..';
import { useNotifications } from '@/features/promotions/hooks';
import { usePromotionsContent } from '@/features/promotions/api';
import { hasNewContent } from '@/features/promotions/utils';
import { useClusterId } from '@/hooks';
import PromoBannerProvider from '@/context/PromoBanner';

jest.mock('@/features/promotions/hooks', () => ({
    useNotifications: jest.fn(),
}));

jest.mock('@/features/promotions/api', () => ({
    usePromotionsContent: jest.fn(),
}));

jest.mock('@/features/promotions/utils', () => ({ hasNewContent: jest.fn() }));

jest.mock('@/hooks', () => ({ useClusterId: jest.fn() }));

describe('<PromotionsBanner />', () => {
    const config = {
        bannerLink: 'http://banner-link',
        bannerText: 'banner-text',
    };

    const renderComponent = () =>
        render(
            <PromoBannerProvider>
                <PromotionsBanner />
            </PromoBannerProvider>,
        );

    beforeEach(() => {
        jest.mocked(useNotifications).mockReturnValue({
            notificationsDisabled: false,
            notificationsEnabled: true,
        });
        jest.mocked(usePromotionsContent).mockReturnValue(config);
        jest.mocked(hasNewContent).mockReturnValue(false);
    });
    it('should show the banner', () => {
        renderComponent();

        expect(screen.getByText(config.bannerText)).toBeInTheDocument();
    });

    it('should not show the banner if notifications are disabled', () => {
        jest.mocked(useNotifications).mockReturnValue({
            notificationsDisabled: true,
            notificationsEnabled: false,
        });

        renderComponent();

        expect(screen.queryByText(config.bannerText)).not.toBeInTheDocument();
    });

    it('should close the banner and show it again when the content has changed', () => {
        const newConfig = {
            bannerLink: 'new-link',
            bannerText: 'new-text',
        };
        const { rerender } = renderComponent();
        fireEvent.click(screen.getByTestId('promotions-banner-close-button'));
        expect(screen.queryByText(config.bannerText)).not.toBeInTheDocument();

        jest.mocked(hasNewContent).mockReturnValue(true);
        jest.mocked(usePromotionsContent).mockReturnValue(newConfig);
        rerender(
            <PromoBannerProvider>
                <PromotionsBanner />
            </PromoBannerProvider>,
        );

        expect(screen.getByText(newConfig.bannerText)).toBeInTheDocument();
    });

    it('should have the expected url', () => {
        const clusterId = 'mock-id';
        jest.mocked(useClusterId).mockReturnValue(clusterId);

        renderComponent();

        expect(screen.getByRole('link')).toHaveProperty(
            'href',
            `http://banner-link/?utm_source=whisker&utm_medium=promo-banner-link&utm_campaign=oss-ui&whisker_id=${clusterId}`,
        );
    });
});
