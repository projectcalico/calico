import React from 'react';
import { FlowLogAction } from '../../../types/render';
import { StatusIndicator } from '@/libs/tigera/ui-components/components/common';

const ActionColorMap: Record<FlowLogAction, string> = {
    allow: 'tigeraGreen.900',
    deny: 'tigeraRed.1000',
    pass: 'tigeraGrey.400',
    log: 'tigeraGrey.400',
};

type FlowLogActionIndicatorProps = {
    action: FlowLogAction;
};

const FlowLogActionIndicator: React.FC<FlowLogActionIndicatorProps> = ({
    action,
}) => <StatusIndicator color={ActionColorMap[action]} label={action} />;

export default FlowLogActionIndicator;
