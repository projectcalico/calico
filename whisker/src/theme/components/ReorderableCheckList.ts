export default {
    parts: [
        'root',
        'list',
        'item',
        'checkbox',
        'footer',
        'header',
        'body',
        'footerButton',
    ],
    sizes: {
        sm: {
            checkbox: {
                '.chakra-checkbox__label': {
                    fontSize: 'sm',
                },
            },
            footerButton: {
                fontSize: 'sm',
            },
        },
    },
    baseStyle: {
        root: {
            pb: 2,
            bg: 'experimental-token-elevation-overlay',
        },
        item: {
            backgroundColor: 'experimental-token-elevation-overlay-surface',
            border: '1px solid',
            borderColor: 'tigera-color-outline-on-surface-container-high',
            _dark: {
                border: 'none',
                // backgroundColor: 'tigeraGrey.1000',
            },
            borderRadius: '5',
            p: '3',
            mb: '2',
            styleType: 'none',
            justifyContent: 'space-between',
            _active: {
                cursor: 'grab',
                bg: 'experimental-token-bg-neutral',
            },
        },
        checkbox: {
            '.chakra-checkbox__label': {
                fontSize: 'xs',
                fontWeight: '700',
            },
        },
        list: {
            styleType: 'none',
            maxHeight: '750px',
            overflow: 'auto',
        },
        footer: {
            borderTop: '1px solid',
            borderColor: 'tigera-color-outline-on-surface-container-high',
            pb: 4,
        },
        header: {
            pb: 2,
        },
        body: {
            pb: 2,
        },
    },
};
