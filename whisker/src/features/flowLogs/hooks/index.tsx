import { FlowLog } from '@/types/render';
import React from 'react';
import { getSeconds } from '../utils';
import { usePromoBanner } from '@/context/PromoBanner';

export const useMaxStartTime = (flowLogs: FlowLog[]) => {
    const max = React.useRef(0);

    React.useEffect(() => {
        if (flowLogs[0]?.start_time.getTime() ?? 0 > max.current) {
            max.current = flowLogs?.[0]?.start_time.getTime();
        }
    }, [flowLogs.length]);

    return max;
};

const MAX_ELAPSED_TIME = 0.1;
export const useShouldAnimate = (startTime: number, totalItems: number) => {
    const animatedMap = React.useRef<Map<string, string>>(new Map());
    const rowsAddedTime = React.useRef<Date | null>(null);
    const previousLength = React.useRef(totalItems);

    if (totalItems !== previousLength.current) {
        previousLength.current = totalItems;
        animatedMap.current = new Map();
        rowsAddedTime.current = new Date();
    }

    const shouldAnimate = (flowLog: FlowLog) => {
        const elapsedTime =
            getSeconds(new Date()) - getSeconds(rowsAddedTime.current);

        if (elapsedTime > MAX_ELAPSED_TIME) {
            return false;
        }

        if (animatedMap.current.has(flowLog.id)) {
            return false;
        }

        const animate =
            flowLog.start_time.getTime() > startTime && startTime !== 0;

        if (animate) {
            animatedMap.current.set(flowLog.id, flowLog.id);
        }

        return animate;
    };

    return shouldAnimate;
};

const bannerHeight = 40;
const headerHeight = 60;
const containerPadding = 5;
const omniFiltersHeight = 46;
const tabsHeight = 34;

export const useFlowLogsHeightOffset = () => {
    const promoBanner = usePromoBanner();
    const heights =
        headerHeight + containerPadding + omniFiltersHeight + tabsHeight;

    return promoBanner.state.isVisible ? heights + bannerHeight : heights;
};
