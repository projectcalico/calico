import type { ComponentMultiStyleConfig } from '@chakra-ui/react';

export default {
    parts: ['triggerText', 'triggerActive', 'content'],
    baseStyle: {
        triggerText: {
            fontWeight: 400,
            marginLeft: 1,
        },
        triggerActive: {
            fontWeight: 'bold',
            backgroundColor: 'tigeraBlueLight',
            color: 'tigeraBlueDark',
            _hover: {
                backgroundColor: 'tigeraBlueLight',
            },
            _dark: {
                backgroundColor: 'tigeraBlueMediumAlpha40',
                color: 'tigeraBlueMedium40',
                _hover: {
                    backgroundColor: 'tigeraBlueMediumAlpha40',
                },
            },
        },
        content: {
            boxShadow: '0px 0px 8px #dcdde0 !important',
            borderColor: 'tigeraGrey.300',
            borderWidth: '1px',
            borderRadius: 'md',
            fontSize: 'sm',
            width: '300px',
            _focus: {
                boxShadow: 'none',
                outline: 'none',
            },
        },
    },
} as ComponentMultiStyleConfig;
