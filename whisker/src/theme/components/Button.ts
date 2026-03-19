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
        // needed?
        xl: {
            maxHeight: '56px',
            height: '56px',
            py: '4',
            px: '8',
        },
    },
    variants: {
        solid: (props: ButtonProps) => {
            const colorSchemes = {
                default: {
                    fontSize: 'xs',
                    backgroundColor: 'experimental-token-bg-brand',
                    color: 'experimental-token-on-bg-brand',

                    _active: {
                        bg: 'experimental-token-bg-brand:pressed',
                    },
                    _hover: {
                        bg: 'experimental-token-bg-brand:hovered',
                        _disabled: {
                            backgroundColor: 'experimental-token-bg-brand',
                        },
                    },
                },
                'on-primary': {
                    bg: 'experimental-token-bg-on-brand',
                    color: 'experimental-token-fg-default',

                    _active: {
                        bg: 'experimental-token-bg-on-brand:pressed',
                    },
                    _hover: {
                        bg: 'experimental-token-bg-on-brand:hovered',
                        _disabled: {
                            bgColor: 'experimental-token-bg-on-brand',
                        },
                    },
                },
                green: {
                    bg: 'experimental-token-bg-success',
                    color: 'experimental-token-on-bg-success',

                    _active: {
                        bg: 'experimental-token-bg-success:pressed',
                    },
                    _hover: {
                        bgColor: 'experimental-token-bg-success:hovered',
                        _disabled: {
                            bgColor: 'experimental-token-bg-success',
                        },
                    },
                },
                white: {
                    svg: {
                        fill: 'experimental-token-black',
                        color: 'experimental-token-black',
                    },
                    color: 'experimental-token-black',
                    bg: 'experimental-token-white',
                    _hover: {
                        bg: 'experimental-color-neutral.50',
                    },
                    _active: {
                        bg: 'experimental-color-neutral.100',
                    },
                    _dark: {
                        bg: 'experimental-color-neutral.50',
                        _hover: {
                            bg: 'experimental-color-neutral.100',
                        },
                        _active: {
                            bg: 'experimental-color-neutral.200',
                        },
                    },
                },
                info: {
                    svg: {
                        fill: 'experimental-token-on-bg-info',
                        color: 'experimental-token-on-bg-info',
                    },
                    color: 'experimental-token-on-bg-info',
                    bg: 'experimental-token-bg-info',
                    _hover: {
                        bg: 'experimental-token-bg-info:hovered',
                    },
                    _active: {
                        bg: 'experimental-token-bg-info:pressed',
                    },
                    fontSize: 'xs',
                },
                danger: {
                    fontSize: 'xs',
                    svg: {
                        fill: 'experimental-token-on-bg-danger',
                        color: 'experimental-token-on-bg-danger',
                    },
                    bg: 'experimental-token-bg-danger',
                    color: 'experimental-token-on-bg-danger',
                    _active: {
                        bg: 'experimental-token-bg-danger:pressed',
                    },
                    _hover: {
                        bg: 'experimental-token-bg-danger:hovered',
                    },
                },
                neutral: {
                    fontSize: 'xs',
                    bg: 'experimental-token-bg-neutral',
                    color: 'experimental-token-fg-default',
                    shadow: 'none',
                    svg: {
                        fill: 'experimental-token-fg-default',
                    },
                    _hover: {
                        bg: 'experimental-token-bg-neutral:hovered',
                        _disabled: {
                            bg: 'experimental-token-bg-neutral',
                        },
                    },
                    _active: {
                        bg: 'experimental-token-bg-neutral:pressed',
                        _disabled: {
                            bg: 'experimental-token-bg-neutral',
                        },
                    },
                },
                'neutral-overlay': {
                    fontSize: 'xs',
                    bg: 'experimental-color-neutral.800',
                    color: 'experimental-token-fg-default',
                    shadow: 'none',
                    svg: {
                        fill: 'experimental-token-fg-default',
                    },
                    _hover: {
                        bg: 'experimental-color-neutral.700',
                        _disabled: {
                            bg: 'experimental-token-bg-neutral',
                        },
                    },
                    _active: {
                        bg: 'experimental-color-neutral.600',
                        _disabled: {
                            bg: 'experimental-token-bg-neutral',
                        },
                    },
                },
                'neutral-solid': {
                    fontSize: 'xs',
                    bg: 'experimental-token-bg-neutral-solid',
                    color: 'experimental-token-fg-default',
                    shadow: 'none',
                    svg: {
                        fill: 'experimental-token-fg-default',
                    },
                    _hover: {
                        bg: 'experimental-token-bg-neutral-solid:hovered',
                        _disabled: {
                            bg: 'experimental-token-bg-neutral',
                        },
                    },
                    _active: {
                        bg: 'experimental-token-bg-neutral-solid:pressed',
                        _disabled: {
                            bg: 'experimental-token-bg-neutral',
                        },
                    },
                },
            };

            return (
                (colorSchemes as Record<string, any>)[
                    props.colorScheme ?? ''
                ] ?? colorSchemes.default
            );
        },
        outline: (props: ButtonProps) => {
            const colorSchemes = {
                default: {
                    fontSize: 'xs',
                    bg: 'experimental-token-bg-neutral-base',
                    _dark: {
                        bg: 'experimental-token-bg-empty',
                    },
                    color: 'experimental-token-fg-brand',
                    borderColor: 'experimental-token-border-brand',
                    svg: {
                        fill: 'experimental-token-fg-brand',
                    },
                    _hover: {
                        bg: 'experimental-token-bg-neutral-base',
                        color: 'experimental-token-fg-brand:hovered',
                        borderColor: 'experimental-token-border-brand:hovered',
                        svg: {
                            fill: 'experimental-token-fg-brand:hovered',
                        },
                    },
                    _active: {
                        bg: 'experimental-token-bg-neutral-base',
                        color: 'experimental-token-fg-brand:pressed',
                        borderColor: 'experimental-token-border-brand:pressed',
                        svg: {
                            fill: 'experimental-token-fg-brand:pressed',
                        },
                    },
                },
                neutral: {
                    fontSize: 'xs',
                    fontWeight: 'medium',
                    bg: 'experimental-token-bg-neutral-base',
                    _dark: {
                        bg: 'experimental-token-bg-empty',
                    },
                    borderColor: 'experimental-token-border-default',
                    svg: {
                        fill: 'experimental-token-fg-support',
                    },
                    _hover: {
                        bg: 'experimental-token-bg-neutral-subtle:hovered',
                        _dark: {
                            bg: 'experimental-token-bg-neutral-subtle:hovered',
                        },
                    },
                    _active: {
                        bg: 'experimental-token-bg-neutral-subtle:pressed',
                        _dark: {
                            bg: 'experimental-token-bg-neutral-subtle:pressed',
                        },
                    },
                },
            };

            return (
                (colorSchemes as Record<string, any>)[
                    props.colorScheme ?? ''
                ] ?? colorSchemes.default
            );
        },
        ghost: (props: ButtonProps) => {
            const colorSchemes = {
                default: {
                    fontSize: 'xs',
                    bg: 'experimental-token-bg-empty',
                    color: 'experimental-token-fg-brand',
                    shadow: 'none',
                    svg: {
                        fill: 'experimental-token-fg-brand',
                    },
                    _hover: {
                        bg: 'experimental-token-bg-empty',
                        color: 'experimental-token-fg-brand:hovered',
                        svg: {
                            fill: 'experimental-token-fg-brand:hovered',
                        },
                    },
                    _active: {
                        bg: 'experimental-token-bg-empty',
                        color: 'experimental-token-fg-brand:pressed',
                        svg: {
                            fill: 'experimental-token-fg-brand:pressed',
                        },
                    },
                },
                neutral: {
                    fontSize: 'xs',
                    bg: 'experimental-token-bg-empty',
                    color: 'experimental-token-fg-default',
                    shadow: 'none',
                    svg: {
                        fill: 'experimental-token-fg-default',
                    },
                    _hover: {
                        bg: 'experimental-token-bg-empty',
                        color: 'experimental-token-fg-support',
                        svg: {
                            fill: 'experimental-token-fg-support',
                        },
                    },
                    _active: {
                        bg: 'experimental-token-bg-empty',
                        color: 'experimental-token-fg-subtle',
                        svg: {
                            fill: 'experimental-token-fg-subtle',
                        },
                    },
                },
            };

            return (
                (colorSchemes as Record<string, any>)[
                    props.colorScheme ?? ''
                ] ?? colorSchemes.default
            );
        },
        neutral: {
            fontSize: 'xs',
            bg: 'experimental-token-bg-neutral-subtle',
            color: 'experimental-token-fg-default',
            shadow: 'none',
            svg: {
                fill: 'experimental-token-fg-default',
            },
            _hover: {
                bg: 'experimental-token-bg-neutral-subtle:hovered',
            },
            _active: {
                bg: 'experimental-token-bg-neutral-subtle:pressed',
            },
        },
        solidAlt: {
            fontSize: 'sm',
            color: 'experimental-token-fg-default',
            backgroundColor: 'experimental-token-bg-neutral',
            fontWeight: 'medium',
            boxShadow: 'unset',
            _active: {
                bg: 'experimental-token-bg-neutral:pressed',
                _disabled: {
                    bg: 'experimental-token-bg-neutral',
                },
            },
            _hover: {
                bgColor: 'experimental-token-bg-neutral:hovered',
                _disabled: {
                    bg: 'experimental-token-bg-neutral',
                },
            },

            '&[aria-expanded="true"]': {
                bg: 'experimental-token-bg-neutral:pressed',
            },
        },
        icon: {
            boxShadow: 'none',
            height: '6',
            width: '6',
            minWidth: 6,
            bg: 'experimental-token-bg-neutral-subtle',

            _active: {
                bg: 'experimental-token-bg-neutral-subtle:pressed',
            },
            _hover: {
                bg: 'experimental-token-bg-neutral-subtle:hovered',
                _disabled: {
                    bg: 'experimental-token-bg-neutral-subtle',
                },
            },
        },
        gradient: {
            color: 'experimental-token-fg-inverted',
            background: 'experimental-token-bg-gradient-promo',
            textShadow: '0px 1px 3px rgba(0,0,0,0.4)',
            _dark: {
                textShadow: 'unset',
            },
            transition:
                'background-color 300ms ease-in-out, transform 150ms ease-in-out, box-shadow 150ms ease-in-out',
            _hover: {
                color: 'experimental-token-fg-inverted!important',
                backgroundColor: 'experimental-token-bg-gradient-promo:hovered',
                transform: 'translateY(-1px)',
                boxShadow: 'lg',
                _disabled: {
                    background: 'experimental-token-bg-gradient-promo',
                    transform: 'none',
                    boxShadow: 'none',
                },
            },
            _active: {
                color: 'experimental-token-fg-inverted!important',
                backgroundColor: 'experimental-token-bg-gradient-promo:pressed',
            },
            size: 'lg',
            fontSize: 'md',
            p: 6,
            my: 6,
        },
        link: {
            color: 'experimental-token-link',
            background: 'transparent',
            boxShadow: 'none',
            _focus: { boxShadow: 'none' },
            _active: {
                color: 'experimental-token-link:pressed',
            },
        },
    },
};
