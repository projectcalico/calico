import { BannerContent } from '@/types/api';
import { hasNewContent } from '..';

describe('hasNewContent', () => {
    const content: BannerContent = {
        bannerLink: 'link',
        bannerText: 'text',
    };

    const storedContent: BannerContent = {
        bannerLink: 'stored-link',
        bannerText: 'stored-text',
    };

    it('should return false', () => {
        expect(hasNewContent(null, null)).toEqual(false);
    });

    it('should return false when content is null', () => {
        expect(hasNewContent(null, storedContent)).toEqual(false);
    });

    it('should return false when stored content is null', () => {
        expect(hasNewContent(content, null)).toEqual(false);
    });

    it('should return false when there is no difference', () => {
        expect(hasNewContent(content, content)).toEqual(false);
    });

    it('should return true when there is a difference', () => {
        expect(hasNewContent(content, storedContent)).toEqual(true);
    });
});
