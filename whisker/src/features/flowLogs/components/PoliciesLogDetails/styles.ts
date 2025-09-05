export const tableStyles = {
    fontFamily: 'monospace, monospace',
    bg: 'tigera-color-surface',
    w: '100%',

    tr: {
        // fixed widths improve multi-table column alignment
        '&>th:nth-child(1)': {
            w: '220px',
        },
        '&>th:nth-child(2)': {
            w: '180px',
        },
        '&>th:nth-child(3)': {
            w: '190px',
        },
        '&>th:nth-child(4)': {
            w: '120px',
        },
        '&>th:nth-child(5)': {
            w: '110px',
        },
        '&>th:nth-child(6)': {
            w: '116px',
        },
        '&>th:nth-child(7)': {
            w: '116px',
        },
    },
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
