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
            boxShadow:
                'var(--chakra-colors-experimental-token-elevation-overlay-shadow)!important',
            borderColor: 'experimental-token-border-default',
            borderWidth: '1px solid',
            borderRadius: 'md',
            fontSize: 'sm',
            width: '300px',
            _focus: {
                boxShadow: 'none',
                outline: 'none',
            },
        },
        footer: {
            alignItems: 'center',
            justifyContent: 'space-between',
            display: 'flex',
            borderColor: 'tigeraGrey.200',
        },
        header: {
            borderColor: 'tigeraGrey.200',
        },
        body: {
            px: 0,
        },
    },
} as ComponentMultiStyleConfig;
