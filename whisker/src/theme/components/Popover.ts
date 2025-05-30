import { popoverAnatomy as parts } from '@chakra-ui/anatomy';
import { createMultiStyleConfigHelpers } from '@chakra-ui/react';
const { definePartsStyle, defineMultiStyleConfig } =
    createMultiStyleConfigHelpers(parts.keys);

export default defineMultiStyleConfig({
    variants: {
        omniFilter: definePartsStyle({
            header: {
                borderColor: 'tigeraGrey.200',
                _dark: {
                    borderBottomColor: 'tigeraGrey.600',
                },
            },
            footer: {
                display: 'flex',
                borderColor: 'tigeraGrey.200',
                _dark: {
                    borderTopColor: 'tigeraGrey.600',
                },
            },
            body: {
                py: 0,
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
                _dark: {
                    backgroundColor: 'tigeraGrey.1000',
                    boxShadow: 'none!important',
                    border: 'none',
                },
            },
        }),
    },
});
