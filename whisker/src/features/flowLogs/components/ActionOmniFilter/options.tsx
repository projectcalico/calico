import { alpha } from '@/theme/utils';
import { Action } from '@/types/render';
import { CheckIcon, CloseIcon } from '@chakra-ui/icons';

export const radioOptions = [
    {
        value: Action.Allow,
        label: Action.Allow,
        icon: <CheckIcon mr={2} boxSize='3' />,
        styles: {
            _checked: {
                fontWeight: 'bold',
                borderColor: 'tigeraGreen.600',
                borderWidth: '1px',
                color: 'tigeraGreen.600',
                backgroundColor: alpha('tigeraGreen.600', 0.04),
            },
        },
    },
    {
        value: Action.Deny,
        label: Action.Deny,
        icon: <CloseIcon mr={2} boxSize='10px' />,
        styles: {
            _checked: {
                fontWeight: 'bold',
                borderColor: 'tigeraRed.400',
                borderWidth: '1px',
                color: 'tigeraRed.400',
                backgroundColor: alpha('tigeraRed.600', 0.04),
            },
        },
    },
];
