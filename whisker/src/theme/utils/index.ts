import { ThemeTypings } from '@chakra-ui/react';

export const alpha = (color: ThemeTypings['colors'], value: number) => {
    const key = color.replaceAll('.', '-');
    return `color-mix(in srgb, var(--chakra-colors-${key}) ${Math.max(
        Math.min(value * 100, 100),
        0,
    )}%, transparent)`;
};
