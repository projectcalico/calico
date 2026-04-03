import { alpha } from '../utils';

describe('alpha', () => {
    it('should handle fractional opacity values', () => {
        const result = alpha('purple.500' as any, 0.123);
        expect(result).toBe(
            'color-mix(in srgb, var(--chakra-colors-purple-500) 12.3%, transparent)',
        );
    });

    it('should handle color tokens without dots', () => {
        const result = alpha('black' as any, 0.5);
        expect(result).toBe(
            'color-mix(in srgb, var(--chakra-colors-black) 50%, transparent)',
        );
    });

    it('should handle color tokens with CSS variable that has different format', () => {
        const colorWithVar = 'var(--chakra-colors-yellow-500)';
        const result = alpha(colorWithVar as any, 0.8);
        expect(result).toBe(
            'color-mix(in srgb, var(--chakra-colors-yellow-500) 80%, transparent)',
        );
    });
});
