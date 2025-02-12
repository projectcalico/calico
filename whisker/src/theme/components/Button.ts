import { ButtonProps } from '@chakra-ui/react';

export default {
    baseStyle: {
        boxShadow: '0px 1px 2px rgba(0, 0, 0, 0.05)',
        borderRadius: 'base',
        fontStyle: 'normal',
        fontWeight: 'medium',
        lineHeight: '4',
        _focus: {
            boxShadow:
                '0 0 1px 2px rgba(88, 144, 255, .75), 0 1px 1px rgba(0, 0, 0, .15)',
        },
        _hover: {
            // in scneario where button is used as a link
            textDecoration: 'none',
        },
    },
    sizes: {
        sm: {
            maxHeight: '24px',
            py: '1',
            px: '2',
        },
        md: {
            maxHeight: '30px',
            py: '2',
            px: '3',
        },
        lg: {
            maxHeight: '48px',
            py: '2',
            px: '4',
        },
    },
    variants: {
        solid: (props: ButtonProps) => {
            const colorSchemes = {
                default: {
                    fontSize: 'xs',
                    bg: 'tigera-color-primary',
                    color: 'tigeraWhite',

                    _active: {
                        bg: 'tigeraBlueMedium',
                    },
                    _hover: {
                        bgColor: 'tigeraBlueMedium',
                        _disabled: {
                            bgColor: 'tigeraBlueMedium',
                        },
                    },
                    _dark: {
                        color: 'tigeraBlack',
                        _active: {
                            bg: 'tigeraGoldDark',
                        },
                        _disabled: {
                            bgColor: 'tigeraGoldMedium20',
                        },
                        _hover: {
                            bgColor: 'tigeraGoldDark',
                            _disabled: {
                                bgColor: 'tigeraGoldMedium20',
                            },
                        },
                    },
                },
                'on-primary': {
                    bg: 'tigeraWhite',
                    color: 'tigera-color-primary',

                    _active: {
                        bg: 'tigeraGrey.100',
                    },
                    _hover: {
                        bgColor: 'tigeraGrey.100',
                        _disabled: {
                            bgColor: 'tigeraGrey.100',
                        },
                    },
                },
            };

            return (
                (colorSchemes as any)[props.colorScheme ?? ''] ??
                colorSchemes.default
            );
        },
        outline: {
            fontSize: 'xs',
            bg: 'tigeraWhite',
            color: 'tigera-color-primary',
            borderColor: 'tigera-color-primary',
            svg: {
                fill: 'tigeraBlueDark',
            },
            _hover: {
                color: 'tigeraBlueMedium',
                borderColor: 'tigeraBlueMedium',
                bg: 'tigeraWhite',
                svg: {
                    fill: 'tigeraBlueMedium',
                },
            },
            _active: {
                color: 'tigeraBlueMedium',
                borderColor: 'tigeraBlueMedium',
                bg: 'tigeraWhite',
                svg: {
                    fill: 'tigeraBlueMedium',
                },
            },
            _dark: {
                bg: 'transparent',
                _hover: {
                    bg: 'transparent',
                    color: 'tigeraGoldDark',
                    borderColor: 'tigeraGoldDark',
                    svg: {
                        fill: 'tigeraGoldDark',
                    },
                },
                _active: {
                    color: 'tigeraGoldDark',
                    borderColor: 'tigeraGoldDark',
                    bg: 'transparent',
                    svg: {
                        fill: 'tigeraGoldDark',
                    },
                },
            },
        },
        ghost: {
            fontSize: 'xs',
            bg: 'transparent',
            color: 'tigera-color-primary',
            borderColor: 'white',
            shadow: 'none',
            svg: {
                fill: 'tigera-color-primary',
            },
            _hover: {
                color: 'tigeraBlueMedium',
                borderColor: 'tigeraBlueMedium',
                bg: 'white',
                svg: {
                    fill: 'tigeraBlueMedium',
                },
            },
            _active: {
                color: 'tigeraBlueMedium',
                borderColor: 'tigeraBlueMedium',
                bg: 'white',
                svg: {
                    fill: 'tigeraBlueMedium',
                },
            },
            _dark: {
                color: 'tigeraGrey.100',
                _hover: {
                    bg: 'transparent',
                    color: 'tigeraBlueMedium40',
                },
                _focus: { boxShadow: 'none' },
            },
        },
        solidAlt: {
            fontSize: 'sm',
            color: 'tigeraBlack',
            backgroundColor: 'tigeraGrey.100',
            fontWeight: 'medium',
            boxShadow: 'unset',
            _active: {
                bg: 'tigeraGrey.400',
            },
            _hover: {
                bgColor: 'tigeraGrey.200',
            },
            _disabled: {
                color: 'tigeraGrey.1000',
            },
            '&[aria-expanded="true"]': {
                bgColor: 'tigeraGrey.200',
            },
            _dark: {
                color: 'tigeraGrey.200',
                backgroundColor: 'tigeraGrey.1000',
                fontWeight: 'medium',
                boxShadow: 'unset',
                _active: {
                    bg: 'tigeraGrey.800',
                },
                _hover: {
                    bgColor: 'tigeraGrey.800',
                },
                _disabled: {
                    color: 'tigeraGrey.400',
                },
                '&[aria-expanded="true"]': {
                    bgColor: 'tigeraGrey.800',
                },
            },
        },
        icon: {
            boxShadow: 'none',
            height: 5,
            minWidth: 5,
            color: 'tigeraBlack',

            _active: {
                color: 'tigeraGrey.800',
            },
            _hover: {
                color: 'tigeraGrey.600',
                _disabled: {
                    color: 'tigeraGrey.800',
                },
            },
        },
    },
};
