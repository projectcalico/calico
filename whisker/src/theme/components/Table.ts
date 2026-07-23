import { tableAnatomy } from '@chakra-ui/anatomy';
import { createMultiStyleConfigHelpers } from '@chakra-ui/react';

const { defineMultiStyleConfig } = createMultiStyleConfigHelpers(
    tableAnatomy.keys,
);

const defaultStyles = {
    table: {
        bg: 'experimental-token-bg-table-body',
        border: '0px solid',
    },
    th: {
        bg: 'experimental-token-bg-table-header',
        borderTopColor: 'experimental-token-border-default',
        borderBottomColor: 'experimental-token-border-default',
        borderLeftColor: 'experimental-token-border-default',
        borderLeft: 0,
        paddingLeft: '8px',
        borderTop: 0,
        borderRightColor: 'experimental-token-border-default',
        fontSize: 'sm',
        fontWeight: '700',
        letterSpacing: 'normal',
        px: 2,
        py: 2,
        _last: {
            borderRight: 0,
        },
        _first: {
            paddingLeft: 4,
        },
    },
    tr: {
        borderTop: 'none',
    },
    td: {
        fontWeight: '500',
        px: 2,
        py: 2,
        whiteSpace: 'nowrap',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        borderBottom: '1px solid!important',
        borderBottomColor: 'experimental-token-border-default!important',
        fontSize: 'sm',
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

export default defineMultiStyleConfig({
    baseStyle: {
        table: {
            bg: 'yellow', // TODO: FIX THIS BEFORE MERGING
        },
        th: {
            borderColor: 'experimental-token-border-default',
            borderBottom: '1px',
            textTransform: 'capitalize',
        },
        tr: {
            _last: {
                td: {
                    borderBottom: 0,
                },
            },
        },
    },
    sizes: {
        sm: smallStyles,
        md: defaultStyles,
        lg: defaultStyles, //could do with updting if required at some point
    },
    variants: {
        surface: {
            table: {
                bg: 'experimental-token-elevation-surface',
                borderColor: 'experimental-token-border-default',
                borderWidth: '1px',
                borderStyle: 'solid',
            },
            th: {
                bg: 'experimental-token-bg-empty',
                borderRightWidth: '0',
            },
            td: {
                bg: 'experimental-token-bg-empty',
            },
        },
        simple: {
            th: {
                border: 'none',
                color: 'experimental-token-fg-default',
            },
        },
        light: {
            th: {
                borderBottomColor: 'experimental-token-border-default',
                borderBottom: '1px solid',
                bg: 'experimental-token-bg-empty',
                borderRight: 'none',
            },
        },
        modal: {
            table: {
                bg: 'experimental-token-elevation-overlay',
            },
            th: {
                border: 'none',
            },
        },
        innerExpando: {
            table: {
                bg: 'experimental-token-bg-empty',
            },
            td: {
                _first: {
                    verticalAlign: 'top',
                    color: 'tigeraGrey.700',
                    pl: 8,
                },
                _last: {
                    pr: 0,
                },
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
});
