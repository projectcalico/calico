import componentTokens from './componentTokens';

const semanticTokens = {
    // Accent colors
    'tigera-color-primary': {
        _light: 'tigeraBlueDark',
        _dark: 'tigeraGoldMedium',
    },
    'tigera-color-on-primary': {
        _light: 'tigeraWhite',
        _dark: 'tigeraBlack',
    },
    'tigera-color-secondary': {
        _light: 'tigeraGrey.800',
        _dark: 'tigeraGrey.200',
    },
    'tigera-color-on-secondary': {
        _light: 'tigeraWhite',
        _dark: 'tigeraBlack',
    },
    'tigera-color-tertiary': {
        _light: 'tigeraBlueMedium',
        _dark: 'tigeraGoldLight',
    },
    'tigera-color-on-tertiary': {
        _light: 'tigeraWhite',
        _dark: 'tigeraBlack',
    },
    'tigera-color-error': {
        _light: 'tigeraRed.1000',
        _dark: 'tigeraRed.100',
    },
    'tigera-color-on-error': {
        _light: 'tigeraWhite',
        _dark: 'tigeraRed.1000',
    },

    // Container colors
    'tigera-color-primary-container': {
        _light: 'tigeraBlueLight',
        _dark: 'tigeraGoldMedium20',
    },
    'tigera-color-on-primary-container': {
        _light: 'tigeraBlueDark',
        _dark: 'tigeraBlack',
    },
    'tigera-color-secondary-container': {
        _light: 'tigeraGrey.200',
        _dark: 'tigeraGrey.1000',
    },
    'tigera-color-on-secondary-container': {
        _light: 'tigeraBlack',
        _dark: 'tigeraWhite',
    },
    'tigera-color-tertiary-container': {
        _light: 'tigeraGrey.100',
        _dark: 'tigeraBlack',
    },
    'tigera-color-on-tertiary-container': {
        _light: 'tigeraBlueMedium',
        _dark: 'tigeraGoldLight',
    },

    'tigera-color-error-container': {
        _light: 'tigeraRed.100',
        _dark: 'tigeraRed.1000',
    },
    'tigera-color-on-error-container': {
        _light: 'tigeraRed.1000',
        _dark: 'tigeraWhite',
    },

    // Surface colors (neutrals, backgrounds, cards, modals)
    'tigera-color-surface': {
        _light: 'tigeraWhite',
        _dark: 'tigeraBlack',
    },
    'tigera-color-on-surface': {
        _light: 'tigeraBlack',
        _dark: 'tigeraGrey.200',
    },
    'tigera-color-surface-secondary': {
        _light: 'tigeraGrey.100',
        _dark: 'tigeraBlack',
    },
    'tigera-color-on-surface-secondary': {
        _light: 'tigeraBlack',
        _dark: 'tigeraWhite',
    },
    'tigera-color-on-surface-variant': {
        _light: 'tigeraGrey.600',
        _dark: 'tigeraGrey.400',
    },

    // Surface container colors (nested surfaces)
    'tigera-color-surface-container-low': {
        _light: 'tigeraWhite',
        _dark: 'tigeraBlack',
    },
    'tigera-color-on-surface-container-low': {
        _light: 'tigeraBlack',
        _dark: 'tigeraWhite',
    },
    'tigera-color-surface-container': {
        _light: 'tigeraGrey.100',
        _dark: 'tigeraGrey.1000',
    },
    'tigera-color-on-surface-container': {
        _light: 'tigeraBlack',
        _dark: 'tigeraWhite',
    },
    'tigera-color-surface-container-high': {
        _light: 'tigeraGrey.200',
        _dark: 'tigeraGrey.800',
    },
    'tigera-color-on-surface-container-high': {
        _light: 'tigeraBlack',
        _dark: 'tigeraWhite',
    },
    'tigera-color-surface-container-highest': {
        _light: 'tigeraGrey.400',
        _dark: 'tigeraGrey.600',
    },
    'tigera-color-on-surface-container-highest': {
        _light: 'tigeraBlack',
        _dark: 'tigeraBlack',
    },

    // Border colors
    'tigera-color-outline': {
        _light: 'tigeraGrey.200',
        _dark: 'tigeraGrey.1000',
    },
};

export default {
    colors: {
        ...semanticTokens,
        ...componentTokens,
    },
};
