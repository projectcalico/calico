export const tableStyles = {
    fontFamily: 'monospace, monospace',
    bg: 'tigera-color-surface',
    w: '95%',
};

export const headingStyles = {
    size: 'xs',
    mb: 4,
    fontFamily: 'inherit',
    display: 'flex',
    alignItems: 'center',
};

export const infoIconStyles = {
    color: 'tigera-color-primary',
    ml: 2,
    cursor: 'pointer',
    _hover: {
        color: 'tigeraGoldDark',
    },
};

export const triggerButtonStyles = {
    color: 'tigera-color-primary',

    alignItems: 'center',
    cursor: 'pointer',

    _hover: {
        color: 'tigeraGoldDark',
        svg: {
            color: 'tigeraGoldDark',
        },
    },

    svg: { h: 4, w: 4, color: 'tigera-color-primary', mr: 2 },
};

export const triggerTableStyles = {
    bg: 'transparent',
    'td:first-child': {
        fontWeight: 'bold',
        width: '35%',
    },
};
