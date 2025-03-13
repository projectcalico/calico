import { FlowLogsContext } from '@/features/flowLogs/components/FlowLogsContainer';
import OmniFilters from '@/features/flowLogs/components/OmniFilters';
import { useSelectedOmniFilters } from '@/hooks';
import { useOmniFilterData } from '@/hooks/omniFilters';
import PauseIcon from '@/icons/PauseIcon';
import PlayIcon from '@/icons/PlayIcon';
import { Link, TabTitle } from '@/libs/tigera/ui-components/components/common';
import { VirtualizedRow } from '@/libs/tigera/ui-components/components/common/DataTable';
import {
    OmniFilterChangeEvent,
    useOmniFilterUrlState,
} from '@/libs/tigera/ui-components/components/common/OmniFilter';
import {
    OmniFilterParam,
    OmniFilterProperties,
    transformToFlowsFilterQuery,
} from '@/utils/omniFilter';
import {
    AlertStatus,
    Box,
    Button,
    Flex,
    SkeletonCircle,
    Tab,
    TabList,
    Tabs,
    Text,
    ToastPosition,
    useToast,
} from '@chakra-ui/react';
import React from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { streamButtonStyles } from './styles';
import { useFlowLogsStream } from '@/features/flowLogs/api';

const toastProps = {
    duration: 7500,
    variant: 'toast',
    status: 'info' as AlertStatus,
    position: 'top' as ToastPosition,
};

const FlowLogsPage: React.FC = () => {
    const location = useLocation();
    const isDeniedSelected = location.pathname.includes('/denied-flows');
    const defaultTabIndex = isDeniedSelected ? 1 : 0;

    const [urlFilterParams, , setFilterParam, clearFilterParams] =
        useOmniFilterUrlState<typeof OmniFilterParam>(
            OmniFilterParam,
            OmniFilterProperties,
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

    const [omniFilterData, fetchFilter] = useOmniFilterData();
    const selectedOmniFilterData = {};
    const selectedFilters = useSelectedOmniFilters(
        urlFilterParams,
        omniFilterData,
        selectedOmniFilterData,
    );
    const {
        stopStream,
        startStream,
        isDataStreaming,
        data,
        error,
        isWaiting,
        hasStoppedStreaming,
    } = useFlowLogsStream(urlFilterParams);

    const toast = useToast();
    const selectedRowIdRef = React.useRef<string | null>(null);
    const selectedRowRef = React.useRef<VirtualizedRow | null>(null);
    const isWaitingRef = React.useRef<boolean>(false);
    const hasStoppedRef = React.useRef<boolean>(false);
    isWaitingRef.current = isWaiting;
    hasStoppedRef.current = hasStoppedStreaming;

    const onRowClicked = (row: VirtualizedRow) => {
        selectedRowRef.current = row;

        if (hasStoppedRef.current && !selectedRowIdRef.current) {
            return;
        }

        toast.closeAll();
        stopStream();

        if (isDataStreaming || isWaitingRef.current) {
            selectedRowIdRef.current = row.id;
            toast({
                title: 'Flows stream paused',
                description: 'Close all rows to continue streaming flows.',
                ...toastProps,
            });
            stopStream();
        } else if (row.id === selectedRowIdRef.current) {
            selectedRowIdRef.current = null;
            selectedRowRef.current = null;
            toast({
                description: 'Flows stream resumed.',
                ...toastProps,
            });
            startStream();
        } else {
            selectedRowIdRef.current = row.id;
        }
    };

    const onSortClicked = () => {
        selectedRowRef.current?.closeVirtualizedRow();
        selectedRowIdRef.current = null;
    };

    return (
        <Box pt={1}>
            <Flex justifyContent='space-between' alignItems='center' p={2}>
                <OmniFilters
                    onReset={onReset}
                    onChange={onChange}
                    selectedOmniFilters={selectedFilters}
                    omniFilterData={omniFilterData}
                    onRequestFilterData={({ filterParam, searchOption }) =>
                        fetchFilter(
                            filterParam,
                            transformToFlowsFilterQuery(
                                urlFilterParams,
                                filterParam,
                                searchOption,
                            ),
                        )
                    }
                    onRequestNextPage={(filterParam) =>
                        fetchFilter(filterParam)
                    }
                />
                <Flex>
                    {isWaiting && (
                        <Flex gap={2} alignItems='center'>
                            <SkeletonCircle
                                size='10px'
                                startColor='tigeraGoldMedium'
                                endColor='tigeraBlack'
                                speed={1}
                            />
                            <Text fontSize='sm' fontWeight='medium'>
                                Waiting for flows
                            </Text>
                        </Flex>
                    )}
                    {(hasStoppedStreaming || error) && (
                        <Button
                            variant='ghost'
                            onClick={() => {
                                selectedRowRef.current?.closeVirtualizedRow();
                                selectedRowIdRef.current = null;
                                selectedRowRef.current = null;
                                startStream();
                            }}
                            leftIcon={<PlayIcon fill='tigeraGoldMedium' />}
                            sx={streamButtonStyles}
                        >
                            Play
                        </Button>
                    )}
                    {isDataStreaming && (
                        <Button
                            variant='ghost'
                            onClick={stopStream}
                            leftIcon={<PauseIcon fill='tigeraGoldMedium' />}
                            sx={streamButtonStyles}
                        >
                            Pause
                        </Button>
                    )}
                </Flex>
            </Flex>

            {/* {data.map((item, index) => (
                <FlowLog id={item.id} index={index} key={item.id} />
            ))} */}
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
                            onRowClicked,
                            onSortClicked,
                        } satisfies FlowLogsContext
                    }
                />
            </Tabs>
        </Box>
    );
};

export default FlowLogsPage;
