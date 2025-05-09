import { useLocalStorage } from '@/libs/tigera/ui-components/hooks';
import { BannerContent } from '@/types/api';
import React from 'react';
import { usePromotionsContent } from '../../api';
import { useNotifications } from '../../hooks';
import { hasNewContent } from '../../utils';
import Banner from '../Banner';
import { useClusterId } from '@/hooks';
import { usePromoBanner } from '@/context/PromoBanner';

const PromotionsBannerContainer: React.FC = () => {
    const [storedShowBanner, setStoredShowBanner] = useLocalStorage(
        'whisker.showPromotionsBanner',
        true,
    );
    const [storedContent, setStoredContent] = useLocalStorage<
        BannerContent | undefined
    >('whisker.promotionsBannerContent', undefined);
    const { notificationsEnabled, notificationsDisabled } = useNotifications();
    const content = usePromotionsContent(notificationsEnabled) ?? storedContent;
    const clusterId = useClusterId();

    const {
        dispatch,
        state: { isVisible },
    } = usePromoBanner();

    React.useEffect(() => {
        dispatch({ type: storedShowBanner ? 'show' : 'hide' });
    }, []);

    React.useEffect(() => {
        if (content && !storedContent) {
            setStoredContent(content);
        } else if (hasNewContent(content, storedContent)) {
            setStoredContent(content);
            setStoredShowBanner(true);
            dispatch({ type: 'show' });
        }
    }, [content]);

    React.useEffect(() => {
        if (notificationsDisabled) {
            dispatch({ type: 'hide' });
            setStoredContent(undefined);
        }
    }, [notificationsDisabled]);

    return isVisible && storedShowBanner && content ? (
        <Banner
            link={content.bannerLink}
            description={content.bannerText}
            onClose={() => {
                setStoredShowBanner(false);
                dispatch({ type: 'hide' });
            }}
            clusterId={clusterId}
        />
    ) : null;
};

export default PromotionsBannerContainer;
