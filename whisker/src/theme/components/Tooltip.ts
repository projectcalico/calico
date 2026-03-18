import { cssVar } from '@chakra-ui/theme-tools';

const $arrowBg = cssVar('popper-arrow-bg');

export default {
    baseStyle: {
        bg: 'experimental-token-elevation-overlay-inverted',
        [$arrowBg.variable]:
            'var(--chakra-colors-experimental-token-elevation-overlay-inverted)',
        color: 'experimental-token-fg-inverted',
        fontSize: 'sm',
        px: 2,
    },
};
