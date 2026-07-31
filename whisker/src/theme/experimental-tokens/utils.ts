import { ThemeTypings } from '@chakra-ui/react';

/**
 * Transparentize Chakra UI color tokens
 * @param color - Chakra UI (semantic) token
 * @param opacity - Opacity value 0 to 1.
 */
export const alpha = (color: ThemeTypings['colors'], value: number) => {
    let mixIn = color;

    if (!color.includes('var(--chakra-colors-')) {
        mixIn = `var(--chakra-colors-${color.replaceAll('.', '-')})`;
    }

    return `color-mix(in srgb, ${mixIn} ${Math.max(
        Math.min(value * 100, 100),
        0,
    )}%, transparent)`;
};
