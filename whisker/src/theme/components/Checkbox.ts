export default {
    baseStyle: {
        control: {
            borderColor: 'experimental-token-border-bold',
            bg: 'experimental-token-bg-empty',
            _disabled: {
                borderColor: 'experimental-token-border-bold',
                bg: 'experimental-token-bg-empty',
                opacity: 0.5,
            },
            _checked: {
                bg: 'experimental-token-bg-brand',
                border: 'none',
                _hover: {
                    bg: 'experimental-token-bg-brand',
                },
                _disabled: {
                    bg: 'experimental-token-bg-brand',
                },
                _before: {
                    bg: 'experimental-token-on-bg-brand',
                },
            },
            _indeterminate: {
                bg: 'experimental-token-bg-brand',
                border: 'none',
            },
        },
        label: {
            color: 'experimental-token-fg-default',
        },
        icon: {
            color: 'experimental-token-on-bg-brand',
        },
    },
    sizes: {
        control: {
            width: '4',
            height: '18px',
        },
        sm: {
            label: {
                fontStyle: 'normal',
                fontWeight: 'medium',
                fontSize: 'xs',
                lineHeight: 5,
            },
        },

        md: {
            label: {
                fontStyle: 'normal',
                fontWeight: 500,
                fontSize: 'sm',
                lineHeight: '6',
            },
        },
    },
};
