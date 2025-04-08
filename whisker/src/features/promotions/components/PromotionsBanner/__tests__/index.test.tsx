import { fireEvent, render, screen } from '@/test-utils/helper';
import PromotionsBanner from '..';
import { useNotifications } from '@/features/promotions/hooks';
import { usePromotionsContent } from '@/features/promotions/api';
import { hasNewContent } from '@/features/promotions/utils';

jest.mock('@/features/promotions/hooks', () => ({
    useNotifications: jest.fn(),
}));

jest.mock('@/features/promotions/api', () => ({
    usePromotionsContent: jest.fn(),
}));

jest.mock('@/features/promotions/utils', () => ({ hasNewContent: jest.fn() }));

describe('<PromotionsBanner />', () => {
    const config = { bannerLink: 'banner-link', bannerText: 'banner-text' };

    beforeEach(() => {
        jest.mocked(useNotifications).mockReturnValue({
            notificationsDisabled: false,
            notificationsEnabled: true,
        });
        jest.mocked(usePromotionsContent).mockReturnValue(config);
        jest.mocked(hasNewContent).mockReturnValue(false);
    });
    it('should show the banner', () => {
        render(<PromotionsBanner />);

        expect(screen.getByText(config.bannerText)).toBeInTheDocument();
    });

    it('should not show the banner if notifications are disabled', () => {
        jest.mocked(useNotifications).mockReturnValue({
            notificationsDisabled: true,
            notificationsEnabled: false,
        });

        render(<PromotionsBanner />);

        expect(screen.queryByText(config.bannerText)).not.toBeInTheDocument();
    });

    it('should close the banner and show it again when the content has changed', () => {
        const newConfig = {
            bannerLink: 'new-link',
            bannerText: 'new-text',
        };
        const { rerender } = render(<PromotionsBanner />);
        fireEvent.click(screen.getByTestId('promotions-banner-close-button'));
        expect(screen.queryByText(config.bannerText)).not.toBeInTheDocument();

        jest.mocked(hasNewContent).mockReturnValue(true);
        jest.mocked(usePromotionsContent).mockReturnValue(newConfig);
        rerender(<PromotionsBanner />);

        expect(screen.getByText(newConfig.bannerText)).toBeInTheDocument();
    });
});
