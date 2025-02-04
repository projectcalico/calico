export default {
    baseStyle: {
        fontStyle: 'normal',
        fontWeight: 'semibold',
        fontSize: 'xxs',
        lineHeight: '4',
        color: 'tigera-color-primary',
        svg: {
            fill: 'tigera-color-primary',
            color: 'tigera-color-primary',
        },
        _hover: {
            color: 'tigeraBlueMedium',
            textDecoration: 'none',
            svg: {
                fill: 'tigeraBlueMedium',
                color: 'tigeraBlueMedium',
            },
        },
        _focus: {
            boxShadow: 'none',
        },
        ':focus:not(:focus-visible)': {
            outline: 'none',
        },
        _dark: {
            _hover: {
                color: 'tigeraGoldMedium40',
                textDecoration: 'none',
                svg: {
                    fill: 'tigeraGoldMedium40',
                    color: 'tigeraGoldMedium40',
                },
            },
        },
    },
    variants: {
        underlined: {
            fontSize: 'xs',
            fontWeight: '500',
            _hover: {
                textDecoration: 'underline',
            },
            _dark: {
                _hover: {
                    textDecoration: 'underline',
                },
            },
        },
    },
};
