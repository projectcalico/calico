import { useStream } from '@/api';
import { FlowLogsContext } from '@/features/flowLogs/components/FlowLogsContainer';
import PauseIcon from '@/icons/PauseIcon';
import PlayIcon from '@/icons/PlayIcon';
import { Link, TabTitle } from '@/libs/tigera/ui-components/components/common';
import {
    OmniFilterChangeEvent,
    useOmniFilterUrlState,
} from '@/libs/tigera/ui-components/components/common/OmniFilter';
import { FlowLog } from '@/types/api';
import {
    OmniFilterData,
    OmniFilterParam,
    OmniFilterProperties,
    SelectedOmniFilterData,
} from '@/utils/omniFilter';
import { Box, Button, Flex, Tab, TabList, Tabs } from '@chakra-ui/react';
import React from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import OmniFilters from '@/features/flowLogs/components/OmniFilters';
import { useSelectedOmniFilters } from '@/hooks';
import { streamButtonStyles } from './styles';

// todo: to use state management after backend integration
const omniFilterData: OmniFilterData = {
    namespace: {
        filters: [],
        isLoading: false,
    },
    policy: {
        filters: [],
        isLoading: false,
    },
    source_namespace: {
        filters: [],
        isLoading: false,
    },
    dest_namespace: {
        filters: [],
        isLoading: false,
    },
};
const selectedOmniFilterData: SelectedOmniFilterData = {
    namespace: {
        filters: [],
        isLoading: false,
    },
    policy: {
        filters: [],
        isLoading: false,
    },
    source_namespace: {
        filters: [],
        isLoading: false,
    },
    dest_namespace: {
        filters: [],
        isLoading: false,
    },
};

const FlowLogsPage: React.FC = () => {
    const location = useLocation();
    const isDeniedSelected = location.pathname.includes('/denied-flows');
    const defaultTabIndex = isDeniedSelected ? 1 : 0;

    const [urlFilterParams, , setFilterParam, clearFilterParams, ,] =
        useOmniFilterUrlState<typeof OmniFilterParam>(
            OmniFilterParam,
            OmniFilterProperties,
        );

    const selectedFilters = useSelectedOmniFilters(
        urlFilterParams,
        omniFilterData,
        selectedOmniFilterData,
    );

    const onChange = (event: OmniFilterChangeEvent) => {
        setFilterParam(
            event.filterId,
            event.filters.map((filter) => filter.value),
            undefined,
        );
    };

    const onReset = () => {
        clearFilterParams();
    };

    const { stopStream, startStream, isStreaming, isFetching, data, error } =
        useStream<FlowLog>('flows?watch=true');

    return (
        <Box pt={1}>
            <Flex justifyContent='space-between' alignItems='center' p={2}>
                <OmniFilters
                    onReset={onReset}
                    onChange={onChange}
                    selectedFilters={selectedFilters}
                />

                <Flex>
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
