import { BannerContent } from '@/types/api';

export const hasNewContent = (
    content: BannerContent | null,
    cached: BannerContent | null,
) =>
    !!content &&
    !!cached &&
    (content.bannerLink !== cached.bannerLink ||
        content.bannerText !== cached.bannerText);
