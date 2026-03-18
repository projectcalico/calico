export const SelectStyles = {
    option: {
        fontWeight: 'normal',
        px: 2.5,
        py: 2,
        fontSize: 'sm',
        minWidth: 'fit-content',
        transition: 'background-color 0.1s ease-in-out',
        backgroundColor: 'experimental-token-bg-neutral-subtle',
        color: 'experimental-token-fg-default',
        _focus: {
            backgroundColor: 'experimental-token-bg-neutral-subtle:hovered',
        },
        _active: {
            backgroundColor: 'experimental-token-bg-neutral-subtle:pressed',
        },
    },
    menu: {
        mt: 1,
        boxShadow:
            'var(--chakra-colors-experimental-token-elevation-overlay-shadow)!important',
        borderColor: 'experimental-token-border-default',
        borderRadius: 'md',
        borderWidth: '1px',
    },
    menuList: {
        pt: 0,
        pb: 0,
        _dark: {
            boxShadow: 'none',
            border: 'none',
        },
    },
};

export default {
    control: (provided: any) => ({
        ...provided,
        height: '42px',
        boxShadow: 'none',
        '&[data-invalid="true"]': { boxShadow: 'none' },
        bg: 'experimental-token-bg-input!important',
        border: 'experimental-token-border-default',
        fontSize: 'sm',
    }),
    container: (provided: any) => ({
        ...provided,
        width: 'full',
    }),

    clearIndicator: (provided: any) => ({
        ...provided,
        fontSize: '0.60rem',
        color: 'experimental-token-fg-subtle',
        '--close-button-size': '10px',
        ':hover': {
            bg: 'unset',
            color: 'experimental-token-fg-support',
        },
    }),

    indicatorsContainer: (provided: any) => ({
        ...provided,
        fontSize: 'xl',
    }),
    multiValueRemove: (provided: any) => ({
        ...provided,
        fontSize: 'sm',
    }),
    menu: (provided: any) => ({
        ...provided,
        ...SelectStyles.menu,
    }),
    menuList: (provided: any) => ({
        ...provided,
        ...SelectStyles.menuList,
    }),
    noOptionsMessage: (state: any) => ({
        ...state,
        textAlign: 'left',
        px: 4,
    }),
    option: (state: any) => ({
        ...state,
        ...SelectStyles.option,
    }),
    dropdownIndicator: (provided: any) => ({
        ...provided,
        bg: 'transparent',
        fontSize: 'xl',
        px: 2,
        cursor: 'inherit',
        color: 'experimental-token-fg-support',
    }),
    indicatorSeparator: (provided: any) => ({
        ...provided,
        display: 'none',
    }),
    singleValue: (provided: any) => ({
        ...provided,
    }),
    placeholder: (provided: any) => ({
        ...provided,
        color: 'experimental-token-fg-subtle',
        fontSize: 'sm',
    }),
    multiValue: (provided: any) => ({
        ...provided,
        color: 'experimental-token-fg-default',
        py: 4,
        borderRadius: 2,
        borderWidth: 0,
        bg: 'experimental-color-blue.100',
        _dark: {
            bg: 'experimental-color-medium-gold.200',
            color: 'experimental-token-fg-inverted',
        },
        svg: {
            color: 'white',
        },
        p: 0,
        pr: 1,
        fontSize: 'xs',
        lineHeight: 5,
        height: 6,
        '>span': {
            py: 3,
            px: '5px',
        },
        '>div': {
            opacity: '1!important',
            borderRadius: '0 2px 2px 0',
            height: 6,
            width: 6,
            bg: 'experimental-token-bg-brand',
            _hover: {
                bg: 'experimental-token-bg-brand:hovered',
            },
            _active: {
                bg: 'experimental-token-bg-brand:pressed',
            },
            _dark: {
                _hover: {
                    bg: 'experimental-token-bg-brand:hovered',
                },
                _active: {
                    bg: 'experimental-color-medium-gold.500',
                },
            },
            '>svg': {
                color: 'white',
                _dark: {
                    color: 'experimental-token-fg-inverted',
                },
            },
        },
    }),
};
