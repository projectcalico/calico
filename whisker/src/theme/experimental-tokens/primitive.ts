/**
 * Primitive tokens for edge cases.
 */

import { alpha } from './utils';

export default {
    'experimental-token-white': 'experimental-color-neutral.0',
    'experimental-token-black': 'experimental-color-neutral.1200',
    'experimental-token-dark-gold-subtle': {
        _light: 'experimental-color-dark-gold.100',
        _dark: alpha('experimental-color-dark-gold.400', 0.17),
    },
};
