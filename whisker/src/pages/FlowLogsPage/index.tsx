import {
    useDeniedFlowLogsCount,
    useFlowLogsCount,
} from '@/features/flowLogs/api';
import { FlowLogsContext } from '@/features/flowLogs/components/FlowLogsContainer';
import { Link, TabTitle } from '@/libs/tigera/ui-components/components/common';
import { Tab, TabList, Tabs } from '@chakra-ui/react';
import React from 'react';
import { Outlet, useLocation } from 'react-router-dom';

const FlowLogsPage: React.FC = () => {
    const location = useLocation();
    const isDeniedSelected = location.pathname.includes('/denied-flows');
    const allFlowsCount = useFlowLogsCount();
    const deniedFlowsCount = useDeniedFlowLogsCount();
    const defaultTabIndex = isDeniedSelected ? 1 : 0;

    return (
        <>
            <Tabs defaultIndex={defaultTabIndex}>
                <TabList>
                    <Link to='flow-logs'>
                        <Tab data-testid='all-flows-tab'>
                            <TabTitle
                                title='All Flows'
                                hasNoData={false}
                                badgeCount={allFlowsCount}
                            />
                        </Tab>
                    </Link>

                    <Link to='denied-flows'>
                        <Tab data-testid='denied-flows-tab'>
                            <TabTitle
                                title='Denied Flows'
                                hasNoData={false}
                                badgeCount={deniedFlowsCount}
                            />
                        </Tab>
                    </Link>
                </TabList>

                <Outlet
                    context={
                        {
                            view: isDeniedSelected ? 'denied' : 'all',
                        } satisfies FlowLogsContext
                    }
                />
            </Tabs>
        </>
    );
};

export default FlowLogsPage;
