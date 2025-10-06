import React from 'react';
import { Box, type HTMLChakraProps } from '@chakra-ui/react';
import { FlowLogAction } from '../../../types/render';
import styles from './styles';

type UnspecifiedAction = 'Unspecified';
type Action = FlowLogAction | UnspecifiedAction;

const ActionColorMap: Record<Action, { fg: string; bg: string }> = {
    Allow: { fg: 'tigeraBlack', bg: 'tigeraGreen.800' },
    Deny: { fg: 'tigeraWhite', bg: 'tigeraRed.1000' },
    Pass: { fg: 'tigeraWhite', bg: 'tigeraGrey.600' },
    Log: { fg: 'tigeraWhite', bg: 'tigeraGrey.600' },
    Unspecified: { fg: 'tigeraWhite', bg: 'tigeraGrey.600' },
};

interface PolicyActionIndicatorProps extends HTMLChakraProps<'div'> {
    action: FlowLogAction | null;
}

const PolicyActionIndicator: React.FC<PolicyActionIndicatorProps> = ({
    action,
    ...rest
}) => (
    <Box
        sx={{
            ...styles,
            bg: ActionColorMap[(action || 'Unspecified') as Action].bg,
            color: ActionColorMap[(action || 'Unspecified') as Action].fg,
        }}
        {...rest}
    >
        {action || 'Unspecified'}
    </Box>
);

export default PolicyActionIndicator;
