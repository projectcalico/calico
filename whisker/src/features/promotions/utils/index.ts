import { BannerContent } from '@/types/api';

export const hasNewContent = (
    content: BannerContent | undefined,
    cached: BannerContent | undefined,
) =>
    !!content &&
    !!cached &&
    (content.bannerLink !== cached.bannerLink ||
        content.bannerText !== cached.bannerText);
