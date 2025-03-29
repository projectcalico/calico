import React from 'react';
import { jsonTabStyles, tableStyles } from './styles';
import { FlowLog } from '@/types/render';
import FlowLogActionIndicator from '@/components/common/FlowLogActionIndicator';
import { LogDetailsView } from '@/libs/tigera/ui-components/components/common';

type FlowLogDetailsProps = {
    flowLog: FlowLog;
};

const FlowLogDetails: React.FC<FlowLogDetailsProps> = ({ flowLog }) => {
    const {
        start_time,
        end_time,
        source_namespace,
        source_name,
        dest_namespace,
        dest_name,
        action,
        policies,
        id: _id,
        ...rest
    } = flowLog;

    const tableData = {
        start_time: start_time.toLocaleTimeString(),
        end_time: end_time.toLocaleTimeString(),
        source_namespace,
        source_name,
        dest_namespace,
        dest_name,
        action: <FlowLogActionIndicator action={action} />,
        policies: JSON.stringify(policies),
        ...rest,
    };

    const jsonData = {
        start_time: start_time.toLocaleTimeString(),
        end_time: end_time.toLocaleTimeString(),
        source_namespace,
        source_name,
        dest_namespace,
        dest_name,
        action,
        policies,
        ...rest,
    };

    return (
        <LogDetailsView
            logDocument={tableData}
            jsonData={jsonData}
            stringifyTableData={false}
            tableStyles={tableStyles}
            jsonTabStyles={jsonTabStyles}
            defaultExpandedJsonNodes={2}
        />
    );
};

export default FlowLogDetails;
