export const CheckboxListLoadingSkeleton = {
    baseStyle: {
        flexDirection: 'column',
        width: 'full',
        marginLeft: '2px',
        px: 3,
    },
    variants: {},
    defaultProps: {},
};

export default {
    parts: ['container', 'checkbox', 'label'],
    baseStyle: {
        container: {
            height: 8,
            width: 'full',
            gap: 3,
            alignItems: 'center',
        },
        checkbox: {
            height: 4,
            width: 4,
        },
        label: {
            height: '14px',
            width: '75%',
        },
    },
};
