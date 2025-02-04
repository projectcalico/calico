import { alertAnatomy } from '@chakra-ui/anatomy';
import { createMultiStyleConfigHelpers, defineStyle } from '@chakra-ui/react';

const { definePartsStyle, defineMultiStyleConfig } =
    createMultiStyleConfigHelpers(alertAnatomy.keys);

const container = defineStyle({
    '&[data-status="info"]': {
        backgroundColor: 'tigeraBlueLight',
        borderColor: 'tigeraBlueMedium',
        _dark: {
            backgroundColor: 'tigeraBlueMediumAlpha40',
            color: 'tigeraBlueMedium40',
        },
    },
    '&[data-status="error"]': {
        backgroundColor: 'tigeraRed.100',
        borderColor: 'tigeraRed.1000',
    },
    '&[data-status="warning"]': {
        backgroundColor: 'tigeraGoldMedium20',
        borderColor: 'tigeraGoldDark',
    },
    '&[data-status="success"]': {
        backgroundColor: 'tigeraGreen.100',
        borderColor: 'tigeraGreen.900',
    },
});

const icon = defineStyle({
    '&[data-status="info"]': {
        color: 'tigeraBlueMedium',
    },
    '&[data-status="error"]': {
        color: 'tigeraRed.1000',
    },
    '&[data-status="warning"]': {
        color: 'tigeraGoldDark',
    },
    '&[data-status="success"]': {
        color: 'tigeraGreen.900',
    },
});

const baseStyle = definePartsStyle({
    container,
    icon,
});

export default defineMultiStyleConfig({ baseStyle });
