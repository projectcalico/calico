import { alpha } from './utils';

/**
 * Backgrounds for buttons, containers etc.
 * Brand is the most important colour and should be used sparingly to highlight the most important actions.
 * Contextual backgrounds are used to express informational context - Success, Danger etc.
 * Neutrals are generally used for everything else.
 *
 * Reference: https://designsystem.backbase.com/latest/design-tokens/semantic-colors/background-colors-mLRqePLh
 */

export default {
    // Brand backgrounds
    'experimental-token-bg-brand': {
        _light: 'experimental-color-blue.900',
        _dark: 'experimental-color-medium-gold.400',
    },
    'experimental-token-bg-brand:hovered': {
        _light: 'experimental-color-blue.800',
        _dark: 'experimental-color-medium-gold.300',
    },
    'experimental-token-bg-brand:pressed': {
        _light: 'experimental-color-blue.700',
        _dark: 'experimental-color-medium-gold.200',
    },
    'experimental-token-bg-brand-subtle': {
        _light: 'experimental-color-blue.50',
        _dark: alpha('experimental-color-medium-gold.400', 0.17),
    },
    'experimental-token-bg-brand-subtle:hovered': {
        _light: 'experimental-color-blue.100',
        _dark: alpha('experimental-color-medium-gold.300', 0.17),
    },
    'experimental-token-bg-brand-subtle:pressed': {
        _light: 'experimental-color-blue.200',
        _dark: alpha('experimental-color-medium-gold.200', 0.17),
    },
    'experimental-token-bg-brand-accent': {
        _light: 'experimental-color-blue.400',
        _dark: 'experimental-color-medium-gold.200',
    },
    'experimental-token-bg-on-brand': {
        _light: 'experimental-color-medium-gold.500',
        _dark: 'experimental-token-bg-neutral-solid',
    },
    'experimental-token-bg-on-brand:hovered': {
        _light: 'experimental-color-medium-gold.600',
        _dark: 'experimental-token-bg-neutral-solid:hovered',
    },
    'experimental-token-bg-on-brand:pressed': {
        _light: 'experimental-color-medium-gold.700',
        _dark: 'experimental-token-bg-neutral-solid:pressed',
    },
    'experimental-token-bg-brand-light': {
        _light: 'experimental-color-blue.100',
        _dark: 'experimental-color-medium-gold.200',
    },
    'experimental-token-on-brand-light': {
        _light: 'experimental-token-fg-default',
        _dark: 'experimental-token-fg-inverted',
    },

    // Contextual backgrounds
    'experimental-token-bg-warning': {
        _light: 'experimental-color-medium-gold.500',
        _dark: 'experimental-color-medium-gold.400',
    },
    'experimental-token-bg-warning:hovered': {
        _light: 'experimental-color-medium-gold.400',
        _dark: 'experimental-color-medium-gold.300',
    },
    'experimental-token-bg-warning:pressed': {
        _light: 'experimental-color-medium-gold.600',
        _dark: 'experimental-color-medium-gold.500',
    },
    'experimental-token-bg-warning-subtle': {
        _light: 'experimental-color-medium-gold.100',
        _dark: alpha('experimental-color-medium-gold.500', 0.2),
    },
    'experimental-token-bg-info': {
        _light: 'experimental-color-medium-blue.600',
        _dark: 'experimental-color-medium-blue.300',
    },
    'experimental-token-bg-info:hovered': {
        _light: 'experimental-color-medium-blue.700',
        _dark: 'experimental-color-medium-blue.200',
    },
    'experimental-token-bg-info:pressed': {
        _light: 'experimental-color-medium-blue.800',
        _dark: 'experimental-color-medium-blue.100',
    },
    'experimental-token-bg-info-subtle': {
        _light: 'experimental-color-medium-blue.100',
        _dark: alpha('experimental-color-medium-blue.400', 0.2),
    },
    'experimental-token-bg-danger': {
        _light: 'experimental-color-red.600',
        _dark: 'experimental-color-red.400',
    },
    'experimental-token-bg-danger:hovered': {
        _light: 'experimental-color-red.700',
        _dark: 'experimental-color-red.300',
    },
    'experimental-token-bg-danger:pressed': {
        _light: 'experimental-color-red.800',
        _dark: 'experimental-color-red.200',
    },
    'experimental-token-bg-danger-subtle': {
        _light: 'experimental-color-red.100',
        _dark: alpha('experimental-color-red.500', 0.2),
    },
    'experimental-token-bg-success': {
        _light: 'experimental-color-green.600',
        _dark: 'experimental-color-green.400',
    },
    'experimental-token-bg-success:hovered': {
        _light: 'experimental-color-green.700',
        _dark: 'experimental-color-green.300',
    },
    'experimental-token-bg-success:pressed': {
        _light: 'experimental-color-green.800',
        _dark: 'experimental-color-green.200',
    },
    'experimental-token-bg-success-subtle': {
        _light: 'experimental-color-green.100',
        _dark: alpha('experimental-color-green.600', 0.2),
    },

    // Selected backgrounds
    'experimental-token-bg-selected': {
        _light: '',
        _dark: '',
    },
    'experimental-token-bg-selected:hovered': {
        _light: '',
        _dark: '',
    },
    'experimental-token-bg-selected:pressed': {
        _light: '',
        _dark: '',
    },

    // Neutral backgrounds
    'experimental-token-bg-empty': {
        _light: 'transparent',
        _dark: 'transparent',
    },
    'experimental-token-bg-neutral-base': {
        _light: 'experimental-color-neutral.0',
        _dark: 'experimental-color-neutral.1200',
    },
    'experimental-token-bg-neutral-subtle': {
        _light: 'experimental-token-bg-empty',
        _dark: 'experimental-token-bg-empty',
    },
    'experimental-token-bg-neutral-subtle:hovered': {
        _light: 'experimental-color-light-alpha.100',
        _dark: 'experimental-color-dark-alpha.100',
    },
    'experimental-token-bg-neutral-subtle:pressed': {
        _light: 'experimental-color-light-alpha.200',
        _dark: 'experimental-color-dark-alpha.200',
    },
    'experimental-token-bg-neutral': {
        _light: 'experimental-color-light-alpha.100',
        _dark: 'experimental-color-dark-alpha.100',
    },
    'experimental-token-bg-neutral:hovered': {
        _light: 'experimental-color-light-alpha.200',
        _dark: 'experimental-color-dark-alpha.200',
    },
    'experimental-token-bg-neutral:pressed': {
        _light: 'experimental-color-light-alpha.300',
        _dark: 'experimental-color-dark-alpha.300',
    },
    'experimental-token-bg-neutral-solid': {
        _light: 'experimental-color-neutral.200',
        _dark: 'experimental-color-neutral.500',
    },
    'experimental-token-bg-neutral-solid:hovered': {
        _light: 'experimental-color-neutral.300',
        _dark: 'experimental-color-neutral.600',
    },
    'experimental-token-bg-neutral-solid:pressed': {
        _light: 'experimental-color-neutral.400',
        _dark: 'experimental-color-neutral.700',
    },
    'experimental-token-bg-input': {
        _light: 'experimental-color-neutral.0',
        _dark: 'experimental-color-neutral.1100',
    },

    // Gradients
    'experimental-token-bg-gradient-promo': {
        _light: 'linear-gradient(93.36deg, var(--chakra-colors-experimental-color-medium-blue-600) 20.03%, transparent 107.66%) var(--chakra-colors-experimental-color-zest-400)',
        _dark: 'linear-gradient(93.36deg, var(--chakra-colors-experimental-color-medium-blue-400) 20.03%, transparent 107.66%) var(--chakra-colors-experimental-color-zest-400)',
    },
    'experimental-token-bg-gradient-promo:hovered': {
        _light: 'experimental-color-zest.500',
        _dark: 'experimental-color-zest.500',
    },
    'experimental-token-bg-gradient-promo:pressed': {
        _light: 'experimental-color-zest.600',
        _dark: 'experimental-color-zest.200',
    },
};
