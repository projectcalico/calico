import { useFlowLogsStream } from '@/features/flowLogs/api';
import FlowLogsContainer from '@/features/flowLogs/components/FlowLogsContainer';
import OmniFilters from '@/features/flowLogs/components/OmniFilters';
import { useMaxStartTime } from '@/features/flowLogs/hooks';
import { useSelectedListOmniFilters } from '@/hooks';
import { useOmniFilterData } from '@/hooks/omniFilters';
import PauseIcon from '@/icons/PauseIcon';
import PlayIcon from '@/icons/PlayIcon';
import { VirtualizedRow } from '@/libs/tigera/ui-components/components/common/DataTable';
import {
    OmniFilterChangeEvent,
    useOmniFilterUrlState,
} from '@/libs/tigera/ui-components/components/common/OmniFilter';
import { FilterHintValues } from '@/types/render';
import { parseStartTime } from '@/utils';
import {
    FilterKey,
    OmniFilterKeys,
    OmniFilterProperties,
    transformToFlowsFilterQuery,
} from '@/utils/omniFilter';
import {
    AlertStatus,
    Box,
    Button,
    Flex,
    SkeletonCircle,
    Text,
    ToastPosition,
    useToast,
} from '@chakra-ui/react';
import React from 'react';
import { streamButtonStyles } from './styles';

const toastProps = {
    duration: 7500,
    variant: 'toast',
    status: 'info' as AlertStatus,
    position: 'top' as ToastPosition,
};

const FlowLogsPage: React.FC = () => {
    const [urlFilterParams, , setFilterParam, clearFilterParams, , ,] =
        useOmniFilterUrlState<typeof OmniFilterKeys>(
            OmniFilterKeys,
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
    const selectedFilters = useSelectedListOmniFilters(
        urlFilterParams,
        omniFilterData,
        selectedOmniFilterData,
    );

    const startTime = parseStartTime(urlFilterParams.start_time?.[0]);
    const filterHintValues = {
        ...urlFilterParams,
        start_time: undefined,
    } as Partial<FilterHintValues>;

    const {
        stopStream,
        startStream,
        isDataStreaming,
        data,
        error,
        isWaiting,
        hasStoppedStreaming,
        isFetching,
        totalItems,
    } = useFlowLogsStream(startTime, filterHintValues);

    const toast = useToast();
    const selectedRowIdRef = React.useRef<string | null>(null);
    const selectedRowRef = React.useRef<VirtualizedRow | null>(null);
    const isWaitingRef = React.useRef<boolean>(false);
    const hasStoppedRef = React.useRef<boolean>(false);
    isWaitingRef.current = isWaiting;
    hasStoppedRef.current = hasStoppedStreaming;

    const maxStartTime = useMaxStartTime(data);

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

    // close virtualized row when data changes
    React.useEffect(() => {
        selectedRowRef.current?.closeVirtualizedRow();
        selectedRowIdRef.current = null;
        selectedRowRef.current = null;
    }, [data.length]);

    const handleMultiChange = (
        values: Partial<Record<FilterKey, string[]>>,
    ) => {
        Object.entries(values).forEach(([key, value]) => {
            setFilterParam(key, value, undefined);
        });
    };

    return (
        <Box pt={1}>
            <Flex justifyContent='space-between' alignItems='center' p={2}>
                <Flex gap={2}>
                    <OmniFilters
                        onReset={onReset}
                        onChange={onChange}
                        selectedListOmniFilters={selectedFilters}
                        omniFilterData={omniFilterData}
                        onRequestFilterData={({ filterParam, searchOption }) =>
                            fetchFilter(
                                filterParam,
                                transformToFlowsFilterQuery(
                                    filterHintValues as FilterHintValues,
                                    filterParam,
                                    searchOption,
                                ),
                            )
                        }
                        onRequestNextPage={(filterParam) =>
                            fetchFilter(filterParam, null)
                        }
                        onMultiChange={handleMultiChange}
                        selectedValues={filterHintValues}
                        startTime={startTime}
                    />
                </Flex>
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

            <FlowLogsContainer
                flowLogs={data}
                error={error}
                onRowClicked={onRowClicked}
                onSortClicked={onSortClicked}
                isFetching={isFetching}
                maxStartTime={maxStartTime.current}
                totalItems={totalItems}
            />
        </Box>
    );
};

export default FlowLogsPage;
