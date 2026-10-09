import React from 'react';
import { jsonTabStyles, tableStyles } from './styles';
import { FlowLog } from '@/types/render';
import { ServiceRef } from '@/types/api';
import FlowLogActionIndicator from '@/components/common/FlowLogActionIndicator';
import { LogDetailsView } from '@/libs/tigera/ui-components/components/common';
import PoliciesLogDetails from '../PoliciesLogDetails';

const TABS_HEIGHT = 38;
const PADDING = 16;
const JSON_TAB_OFFSET = TABS_HEIGHT + PADDING;
type FlowLogDetailsProps = {
    flowLog: FlowLog;
    height?: number;
};

const FlowLogDetails: React.FC<FlowLogDetailsProps> = ({ flowLog, height }) => {
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

    const tableData = {
        ...jsonData,
        action: <FlowLogActionIndicator action={action} />,
        policies: JSON.stringify(policies),
        ...(rest.service && { service: formatService(rest.service) }),
    };

    return (
        <LogDetailsView
            logDocument={tableData}
            jsonData={jsonData}
            stringifyTableData={false}
            tableStyles={tableStyles}
            jsonTabStyles={{
                ...jsonTabStyles,
                maxHeight: `${(height ?? 0) - JSON_TAB_OFFSET}px`,
            }}
            defaultExpandedJsonNodes={2}
            size='lg'
            customTableDataVisualisers={[
                {
                    key: 'policies',
                    component: PoliciesLogDetails,
                },
            ]}
        />
    );
};

const formatService = ({ namespace, name, port, port_name }: ServiceRef) =>
    `${namespace}/${name}:${port_name ? `${port} (${port_name})` : port}`;

export default FlowLogDetails;
