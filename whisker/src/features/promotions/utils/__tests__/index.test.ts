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
        expect(hasNewContent(undefined, undefined)).toEqual(false);
    });
    it('should return false when content is null', () => {
        expect(hasNewContent(undefined, storedContent)).toEqual(false);
    });
    it('should return false when stored content is null', () => {
        expect(hasNewContent(content, undefined)).toEqual(false);
    });
    it('should return false when there is no difference', () => {
        expect(hasNewContent(content, content)).toEqual(false);
    });
    it('should return true when there is a difference', () => {
        expect(hasNewContent(content, storedContent)).toEqual(true);
    });
});
