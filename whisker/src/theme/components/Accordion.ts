import { accordionAnatomy } from '@chakra-ui/anatomy';
import { createMultiStyleConfigHelpers } from '@chakra-ui/react';

const { definePartsStyle, defineMultiStyleConfig } =
    createMultiStyleConfigHelpers(accordionAnatomy.keys);

const baseStyle = definePartsStyle({
    container: {
        // bg: 'experimental-token-elevation-surface',
        borderColor: 'experimental-token-border-default',
    },
    button: {
        backgroundColor: 'experimental-token-bg-neutral-subtle',
        _hover: {
            bg: 'experimental-token-bg-neutral-subtle:hovered',
        },
        _active: {
            bg: 'experimental-token-bg-neutral-subtle:pressed',
        },
    },
});

export default defineMultiStyleConfig({ baseStyle });
