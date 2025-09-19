import { createIcon } from '@chakra-ui/icons';

const TriggeredIcon = createIcon({
    viewBox: '0 0 24 24',
    defaultProps: {
        h: '24px',
        w: '24px',
        stroke: 'currentColor',
        strokeWidth: '2',
        strokeLinecap: 'round',
        strokeLinejoin: 'round',
    },
    path: (
        <>
            <circle cx='12' cy='12' r='10' />
            <path d='m12 16 4-4-4-4' />
            <path d='M8 12h8' />
        </>
    ),
});

export default TriggeredIcon;
