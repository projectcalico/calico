import { createMultiStyleConfigHelpers } from '@chakra-ui/styled-system';

// This function creates a set of function that helps us create multipart component styles.
const helpers = createMultiStyleConfigHelpers([
    'input',
    'iconButton',
    'iconContainer',
]);

export default helpers.defineMultiStyleConfig({
    baseStyle: {
        iconButton: {
            fontSize: '2xs',
            color: 'tigeraGrey.800',
            _dark: {
                color: 'tigeraGrey.200',
                _hover: {
                    color: 'tigeraGrey.400',
                },
            },
        },
        iconContainer: {
            height: 'full',
            maxWidth: '36px',
        },
    },
    variants: {
        outline: {
            input: {
                height: '42px',
            },
        },
        ghost: {
            input: {
                border: 'none',
                _focusVisible: {
                    border: 'none',
                },
            },
        },
    },
    defaultProps: {
        variant: 'ghost',
    },
});
