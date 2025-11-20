import { alpha } from '../utils';

export default {
    variants: {
        solid: {
            backgroundColor: alpha('tigeraGrey.400', 0.2),
        },
        rounded: {
            color: 'tigeraWhite',
            backgroundColor: 'tigeraBlueDark',
            fontSize: 'xs',
            fontWeight: 'semibold',
            px: '0.375rem',
            borderRadius: '8px',
            _dark: {
                color: 'tigeraGrey.800',
                backgroundColor: 'tigeraBlueLight',
            },
        },
    },
};
