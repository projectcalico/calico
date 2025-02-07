export default {
    baseStyle: {
        display: 'flex',
        alignItems: 'center',
        '>div': {
            borderRadius: '50%',
            width: '0.5em',
            height: '0.5em',
        },
        gap: 2,
    },
    sizes: {
        xs: {
            fontSize: 'xxs',
            '>div': {
                width: '6px',
                height: '6px',
            },
        },
        sm: {
            fontSize: 'xs',
        },
        md: {
            fontSize: 'sm',
        },
    },
};

export const statusContainerStyles = { alignItems: 'center', w: 10 };
