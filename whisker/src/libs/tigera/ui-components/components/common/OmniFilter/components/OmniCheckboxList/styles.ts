export const listItemStyles = {
    borderLeftWidth: 2,
    borderLeftColor: 'transparent',
    transition: 'all 0.1s ease-in-out',
    _hover: {
        backgroundColor: 'tigeraGrey.100',
        borderLeftColor: 'tigera-color-primary',
        _dark: {
            backgroundColor: 'tigeraGrey.800',
            borderLeftColor: 'tigeraGoldMedium',
        },
    },
    boxSizing: 'border-box',
    width: 'full',
    px: 3,

    label: {
        mb: 0,
    },
};

export const checkboxStyles = {
    py: 1,
    w: 'full',
};

export const selectedOptionsListStyles = {
    listStyle: 'none',
    maxH: '208px',
    overflowY: 'auto',
};

export const selectedOptionsHeadingStyles = {
    color: 'tigeraGrey.600',
    pl: 3,
    mt: 3,
    _dark: {
        color: 'tigeraGrey.400',
    },
};
