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
    },
};

const inactiveStyles = {
    color: transparentize(`tigeraBlack`, 0.5),
};
export { inactiveStyles };
