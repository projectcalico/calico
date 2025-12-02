import { transparentize } from '@chakra-ui/theme-tools';

export default {
    baseStyle: {},
    variants: {
        subtle: {
            container: {
                bg: 'tigeraGrey.200',
                borderRadius: 'lg',
                fontStyle: 'normal',
                fontWeight: 'normal',
                fontSize: 'xxs',
                lineHeight: '1',
                height: '4',
                minHeight: '4',
                px: '4',
                color: 'tigeraBlack',
                _dark: {
                    color: 'tigeraGrey.100',
                },
            },
        },
        solid: {
            container: {
                bg: 'tigeraGrey.600',
                borderRadius: 'sm',
                lineHeight: '1',
                minHeight: '1',
                fontWeight: 'normal',
                fontSize: 'sm',
                pr: 0,
                gap: 1,
            },
            closeButton: {
                m: 0,
                fontSize: 'sm',
                borderRadius: 'none',
                height: '22px',
                _hover: {
                    bg: 'tigeraGrey.400',
                    color: 'tigeraBlack',
                },
            },
        },
    },
};

const inactiveStyles = {
    color: transparentize(`tigeraBlack`, 0.5),
};
export { inactiveStyles };
