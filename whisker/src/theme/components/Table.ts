const defaultStyles = {
    table: {
        bg: 'tigera-color-surface',
        border: '0px solid',
    },
    th: {
        bg: 'tigera-color-surface',
        border: '1px solid',
        borderTopColor: 'tigera-color-outline',
        borderBottomColor: 'tigera-color-outline',
        borderLeftColor: 'tigera-color-outline',
        borderLeft: 0,
        paddingLeft: '8px',
        borderTop: 0,
        borderRightColor: 'tigera-color-outline',
        fontSize: 'xs',
        fontWeight: '700',
        letterSpacing: 'normal',
        px: 2,
        py: 2,
        color: 'tigera-color-on-surface',
        _last: {
            borderRight: 0,
        },
        _first: {
            paddingLeft: 4,
        },
    },
    tr: {
        borderBottom: '1px',
        borderBottomColor: 'tigera-color-outline',
    },
    td: {
        fontWeight: '500',
        color: 'tigera-color-on-surface',
        px: 2,
        py: 2,
        whiteSpace: 'nowrap',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        border: 'none',
        fontSize: 'xs',
        _first: {
            paddingLeft: 4,
        },
    },
};

const smallStyles = {
    table: defaultStyles.table,
    th: {
        ...defaultStyles.th,
        fontSize: 'xxs',
        fontWeight: '700',
    },
    tr: {
        ...defaultStyles.tr,
    },
    td: {
        ...defaultStyles.td,
        fontSize: 'xxs',
        lineHeight: '18px',
    },
};

export default {
    baseStyle: {
        table: {
            bg: 'tigeraWhite',

            position: 'relative',
        },
        th: {
            borderColor: 'tigeraGrey.200',
            borderBottom: '1px',
            textTransform: 'capitalize',
        },
        tr: {
            _last: {
                borderBottom: 0,
            },
            position: 'sticky',
            top: 0,
        },
        td: {
            borderBottom: 0,
        },
    },
    sizes: {
        sm: smallStyles,
        md: defaultStyles,
        lg: defaultStyles,
    },
    variants: {
        simple: {
            th: {
                borderBottom: '0',
                border: 'none',
                color: 'tigeraBlack',
            },
        },
        light: {
            th: {
                borderBottomColor: 'tigeraGrey.200',
                borderColor: 'tigeraWhite',
                bg: 'tigeraWhite',
                borderRightColor: 'tigeraWhite',
                borderBottom: '0',
            },
        },
        modal: {
            table: {
                bg: 'transparent',
                border: '0px solid',
            },
            th: {
                borderBottomColor: 'tigeraGrey.200',
                borderColor: 'tigeraGrey.200',
                bg: 'tigeraGrey.200',
                borderRightColor: 'tigeraGrey.200',
                borderBottom: '0',
            },
        },
        expando: {
            table: {
                border: 'none',
                fontWeight: '900',
                letterSpacing: 'normal',
            },
            td: {
                whiteSpace: 'break-spaces',
            },
            th: {
                border: '0px',
                background: 'unset',
                textTransform: 'capitalize',
                fontWeight: 700,
                width: '180px',
                fontSize: 'xs',
                verticalAlign: 'top',
                color: 'tigera-color-on-surface',
                lineHeight: '19px',
                paddingLeft: '8',
            },
        },
        drawerContent: {
            overflowX: 'auto',
            table: {
                border: 'none',
                p: 0,
            },
            tr: {
                border: 'none',
            },
            td: {
                whiteSpace: 'break-spaces',
                fontWeight: '400',
                fontFamily: 'Poppins',
                lineHeight: 5,
                verticalAlign: 'top',
                _first: {
                    px: 0,
                },
            },
            th: {
                background: 'unset',
                verticalAlign: 'top',
                textAlign: 'right',
                w: '175px',
                fontFamily: 'Poppins',
                paddingRight: 4,
                lineHeight: 5,
                border: 'none',
                _first: {
                    paddingLeft: 0,
                },
            },
        },
    },
};
