export default {
    baseStyle: {
        tablist: {
            backgroundColor: 'tigera-color-surface',
            color: 'tigera-color-outline',
            button: {
                fontSize: 'xs',
                color: 'tigeraGrey.400',
                '[data-role = "tabTitle"] span': {
                    backgroundColor: 'tigera-color-tab-title',
                },
                _selected: {
                    color: 'tigera-color-on-surface',
                    borderBottom: '2px solid',
                    borderBottomColor: 'tigeraGoldMedium',
                    '[data-role = "tabTitle"] span': {
                        backgroundColor: 'tigera-color-tab-title-selected',
                    },
                },
            },
        },

        tab: {
            fontWeight: 700,
        },
        tabpanel: {
            px: 0,
            bg: 'tigera-color-surface',
        },
    },
};
