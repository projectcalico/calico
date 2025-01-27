import React from 'react';
import FlowLogsList from '../FlowLogsList';
import { useOutletContext } from 'react-router-dom';
import { useFlowLogs } from '../../api';

export type FlowLogsContext = {
    view: 'all' | 'denied';
};

const FlowLogsContainer: React.FC = () => {
    const { view } = useOutletContext<FlowLogsContext>();
    const { data, isLoading, error } = useFlowLogs(
        view === 'denied' ? { action: 'deny' } : undefined,
    );

    return <FlowLogsList flowLogs={data} isLoading={isLoading} error={error} />;
};

export default FlowLogsContainer;
