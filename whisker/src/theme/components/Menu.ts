export default {
    baseStyle: {
        list: {
            boxShadow:
                'var(--chakra-colors-experimental-token-elevation-overlay-shadow)!important',
            borderColor: 'experimental-token-border-default',
            bg: 'experimental-token-elevation-overlay',
        },
        item: {
            color: 'experimental-token-fg-default',
            bg: 'experimental-token-bg-neutral-subtle',
            fontSize: 'xs',
            '&[aria-checked="true"]': {
                fontWeight: 'bold',
            },
            _focus: {
                bg: 'experimental-token-bg-neutral-subtle:hovered',
            },
            _active: {
                bg: 'experimental-token-bg-neutral-subtle:pressed',
            },
        },
        groupTitle: {
            fontSize: 'xs',
        },
    },
};
