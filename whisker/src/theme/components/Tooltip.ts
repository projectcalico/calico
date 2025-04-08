import { cssVar } from '@chakra-ui/theme-tools';

const $arrowBg = cssVar('popper-arrow-bg');

export default {
    baseStyle: {
        bg: 'tigeraGrey.800',
        [$arrowBg.variable]: 'var(--chakra-colors-tigeraGrey-800)',
        color: 'tigeraWhite',
        _dark: {
            bg: 'tigeraGrey.1000',
            [$arrowBg.variable]: 'var(--chakra-colors-tigeraGrey-1000)',
            color: 'tigeraGrey.100',
        },
    },
};
