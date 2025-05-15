export default {
    baseStyle: {
        list: {
            boxShadow: '0px 0px 8px #DCDDE0', // tigeraGrey[300] - can't make work from theme for boxshadow
            borderColor: 'tigeraGrey.300',
            bg: 'tigera-color-surface',
            color: 'tigera-color-on-surface',
            _dark: {
                boxShadow: 'unset',
                borderColor: 'tigeraBlack',
            },
        },
        item: {
            color: 'tigera-color-on-surface',
            bg: 'tigera-color-surface',
            fontSize: 'xs',
            _hover: { bg: 'tigeraBlueMedium', color: 'tigeraWhite' },
            '&[aria-checked="true"]': {
                fontWeight: 'bold',
            },
            _dark: {
                _hover: {
                    bg: 'tigeraGoldMedium40',
                    color: 'tigeraBlack',
                },
            },
        },
        groupTitle: {
            fontSize: 'xs',
        },
    },
};
