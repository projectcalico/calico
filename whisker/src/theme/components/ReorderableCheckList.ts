export default {
    parts: ['root', 'list', 'item', 'checkbox', 'footer', 'header', 'body'],
    baseStyle: {
        root: {
            pb: 2,
            _dark: {
                bg: 'tigera-color-surface-container-high',
            },
        },
        item: {
            backgroundColor: 'tigera-color-surface',
            border: '1px solid',
            borderColor: 'tigera-color-outline-on-surface-container-high',
            borderRadius: '5',
            p: '3',
            mb: '2',
            styleType: 'none',
            justifyContent: 'space-between',
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
