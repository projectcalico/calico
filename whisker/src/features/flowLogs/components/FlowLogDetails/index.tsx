import React from 'react';
import { tableStyles } from './styles';
import { FlowLog } from '@/types/api';
import FlowLogActionIndicator from '@/components/common/FlowLogActionIndicator';
import { LogDetailsView } from '@/libs/tigera/ui-components/components/common';

type FlowLogDetailsProps = {
    flowLog: FlowLog;
};

const FlowLogDetails: React.FC<FlowLogDetailsProps> = ({ flowLog }) => {
    const { start_time, end_time, action, ...rest } = flowLog;

    const tableData = {
        start_time: new Date(start_time).toLocaleTimeString(),
        end_time: new Date(end_time).toLocaleTimeString(),
        action: <FlowLogActionIndicator action={action} />,
        ...rest,
    };

    return (
        <LogDetailsView
            logDocument={tableData}
            stringifyTableData={false}
            tableStyles={tableStyles}
            showTableOnly={true}
        />
    );
};

export default FlowLogDetails;
