export default {
    baseStyle: {
        control: {
            _disabled: {
                bg: 'tigeraGrey.400',
                borderColor: 'tigeraGrey.400',
            },
            _checked: {
                bg: 'tigera-color-primary',
                borderColor: 'tigera-color-primary',
                _focus: {
                    borderColor: 'tigera-color-primary',
                },
            },
            _indeterminate: {
                bg: 'tigera-color-primary',
                borderColor: 'tigera-color-primary',
                _focus: {
                    borderColor: 'tigera-color-primary',
                },
            },
            borderColor: 'tigeraGrey.600',
            bg: 'transparent',
            _dark: {
                borderColor: 'tigeraGrey.400',
                color: 'white',
                _checked: {
                    border: 'none',
                    bg: 'tigeraBlueMedium',
                    borderColor: 'tigeraBlueMedium',
                    _hover: {
                        bg: 'tigeraBlueMedium80',
                        border: 'none',
                    },
                    _disabled: {
                        bg: 'tigeraGrey.800',
                        borderColor: 'tigeraGrey.800',
                    },
                },
                _disabled: {
                    bg: 'tigeraGrey.800',
                    borderColor: 'tigeraGrey.800',
                },
            },
        },
        label: {
            color: 'tigeraGrey',
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
