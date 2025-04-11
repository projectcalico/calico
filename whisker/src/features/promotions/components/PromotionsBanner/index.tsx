import { useLocalStorage } from '@/libs/tigera/ui-components/hooks';
import { BannerContent } from '@/types/api';
import React from 'react';
import { usePromotionsContent } from '../../api';
import { useNotifications } from '../../hooks';
import { hasNewContent } from '../../utils';
import Banner from '../Banner';
import { useClusterId } from '@/hooks';

const PromotionsBannerContainer: React.FC = () => {
    const [showBanner, setShowBanner] = useLocalStorage(
        'whisker.showPromotionsBanner',
        true,
    );
    const [storedContent, setStoredContent] = useLocalStorage<
        BannerContent | undefined
    >('whisker.promotionsBannerContent', undefined);
    const [isOpen, setIsOpen] = React.useState(showBanner);
    const { notificationsEnabled, notificationsDisabled } = useNotifications();
    const content = usePromotionsContent(notificationsEnabled) ?? storedContent;
    const clusterId = useClusterId();

    React.useEffect(() => {
        if (content && !storedContent) {
            setStoredContent(content);
        } else if (hasNewContent(content, storedContent)) {
            setStoredContent(content);
            setShowBanner(true);
            setIsOpen(true);
        }
    }, [content]);

    React.useEffect(() => {
        if (notificationsDisabled) {
            setIsOpen(false);
            setStoredContent(undefined);
        }
    }, [notificationsDisabled]);

    return isOpen && showBanner && content ? (
        <Banner
            link={content.bannerLink}
            description={content.bannerText}
            onClose={() => {
                setShowBanner(false);
                setIsOpen(true);
            }}
            clusterId={clusterId}
        />
    ) : null;
};

export default PromotionsBannerContainer;
