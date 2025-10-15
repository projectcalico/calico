import { cssVar } from '@chakra-ui/theme-tools';

const $arrowBg = cssVar('popper-arrow-bg');

export default {
    baseStyle: {
        fontWeight: 'normal',
        bg: 'tigeraGrey.800',
        [$arrowBg.variable]: 'var(--chakra-colors-tigeraGrey-800)',
        color: 'tigeraWhite',
        _dark: {
            bg: 'tigeraGreyDark.600',
            [$arrowBg.variable]: 'var(--chakra-colors-tigeraGreyDark-600)',
            color: 'tigeraGrey.100',
        },
    },
};
