import { FlowLogsContext } from '@/features/flowLogs/components/FlowLogsContainer';
import { Link, TabTitle } from '@/libs/tigera/ui-components/components/common';
import { Box, Button, Flex, Tab, TabList, Tabs } from '@chakra-ui/react';
import React from 'react';
import { FlowLog } from '@/types/api';
import { Outlet, useLocation } from 'react-router-dom';
import PauseIcon from '@/icons/PauseIcon';
import PlayIcon from '@/icons/PlayIcon';
import { streamButtonStyles } from './styles';
import { useStream } from '@/api';

const FlowLogsPage: React.FC = () => {
    const location = useLocation();
    const isDeniedSelected = location.pathname.includes('/denied-flows');
    const defaultTabIndex = isDeniedSelected ? 1 : 0;

    const { stopStream, startStream, isStreaming, isFetching, data, error } =
        useStream<FlowLog>('flows?watch=true');

    return (
        <Box pt={1}>
            <Flex justifyContent='right' w='100%' py={1} px={4}>
                {isStreaming && !error ? (
                    <Button
                        variant='ghost'
                        onClick={stopStream}
                        leftIcon={<PauseIcon fill='tigeraGoldMedium' />}
                        isLoading={isFetching}
                        sx={streamButtonStyles}
                    >
                        Pause
                    </Button>
                ) : (
                    <Button
                        variant='ghost'
                        onClick={startStream}
                        leftIcon={<PlayIcon fill='tigeraGoldMedium' />}
                        sx={streamButtonStyles}
                    >
                        Play
                    </Button>
                )}
            </Flex>
            <Tabs defaultIndex={defaultTabIndex}>
                <TabList>
                    <Link to='flow-logs'>
                        <Tab data-testid='all-flows-tab'>
                            <TabTitle
                                title='All Flows'
                                hasNoData={false}
                                // badgeCount={allFlowsCount}
                            />
                        </Tab>
                    </Link>

                    <Link to='denied-flows'>
                        <Tab data-testid='denied-flows-tab' isDisabled>
                            <TabTitle
                                title='Denied Flows'
                                hasNoData={false}
                                // badgeCount={deniedFlowsCount}
                            />
                        </Tab>
                    </Link>
                </TabList>

                <Outlet
                    context={
                        {
                            view: isDeniedSelected ? 'denied' : 'all',
                            flowLogs: data,
                            error,
                        } satisfies FlowLogsContext
                    }
                />
            </Tabs>
        </Box>
    );
};

export default FlowLogsPage;
