import React from 'react';
import { FlowLogAction } from '../../../types/render';
import { StatusIndicator } from '@/libs/tigera/ui-components/components/common';

const ActionColorMap: Record<FlowLogAction, string> = {
    Allow: 'tigeraGreen.900',
    Deny: 'tigeraRed.1000',
    Pass: 'tigeraGrey.400',
    Log: 'tigeraGrey.400',
};

type FlowLogActionIndicatorProps = {
    action: FlowLogAction;
};

const FlowLogActionIndicator: React.FC<FlowLogActionIndicatorProps> = ({
    action,
}) => <StatusIndicator color={ActionColorMap[action]} label={action} />;

export default FlowLogActionIndicator;
