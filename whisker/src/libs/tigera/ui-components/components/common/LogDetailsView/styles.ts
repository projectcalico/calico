export default {
    parts: ['root', 'table'],
    baseStyle: {
        root: {
            overflowX: 'auto',
        },
        table: {
            border: 'none',
            fontWeight: '900',
            letterSpacing: 'normal',
            minWidth: '100%',
            '& > tbody > tr > td': {
                borderBottom: 'none',
                whiteSpace: 'normal',
            },
            '& > tbody > tr > th': {
                border: '0px',
                background: 'unset',
                textTransform: 'none',
                fontWeight: 700,
                fontSize: 'sm',
                verticalAlign: 'top',
                color: 'tigera-color-on-surface',
                lineHeight: '19px',
                paddingLeft: '8',
                fontFamily: 'inherit',
                width: '15%',
            },
        },
    },
};
