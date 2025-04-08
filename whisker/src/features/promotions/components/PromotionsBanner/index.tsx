import { useLocalStorage } from '@/libs/tigera/ui-components/hooks';
import React from 'react';
import { usePromotionsContent } from '../../api';
import Banner from '../Banner';
import { BannerContent } from '@/types/api';
import { hasNewContent } from '../../utils';
import { useNotificationsEnabled } from '../../hooks';

const PromotionsBannerContainer: React.FC = () => {
    const [showBanner, setShowBanner] = useLocalStorage(
        'whisker.showPromotionsBanner',
        true,
    );
    const [storedContent, setStoredContent] =
        useLocalStorage<BannerContent | null>(
            'whisker.promotionsBannerContent',
            null,
        );
    const [isOpen, setIsOpen] = React.useState(showBanner);
    const notificationsEnabled = useNotificationsEnabled();
    const content = usePromotionsContent(notificationsEnabled) ?? storedContent;

    React.useEffect(() => {
        if (content && !storedContent) {
            setStoredContent(content);
        } else if (hasNewContent(content, storedContent)) {
            setStoredContent(content);
            setShowBanner(true);
            setIsOpen(true);
        }
    }, [content]);

    return isOpen && showBanner && content && notificationsEnabled ? (
        <Banner
            link={content.bannerLink}
            description={content.bannerText}
            onClose={() => {
                setShowBanner(false);
                setIsOpen(true);
            }}
        />
    ) : null;
};

export default PromotionsBannerContainer;
