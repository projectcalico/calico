const tableTokens = {
    'tigera-color-table-row': {
        _light: 'tigeraWhite',
        _dark: 'tigeraGrey.800',
    },
    'tigera-color-table-row-hover': {
        _light: 'tigeraGrey.100',
        _dark: 'tigeraGrey.600',
    },
    'tigera-color-table-row-expanded': {
        _light: 'tigeraDarkBlue',
        _dark: 'tigeraBlueMediumAlpha40',
    },
    'tigera-color-on-table-row-expanded': {
        _light: 'tigeraWhite',
        _dark: 'tigeraBlueMedium40',
    },
};

const tabsTokens = {
    'tigera-color-tab-title': {
        _light: 'tigeraGrey.100',
        _dark: 'tigeraBlueMediumAlpha40',
    },
    'tigera-color-tab-title-selected': {
        _light: 'tigeraGrey.300',
        _dark: 'tigeraBlueMediumAlpha40',
    },
};

export default {
    ...tableTokens,
    ...tabsTokens,
};
