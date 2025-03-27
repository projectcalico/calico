import { renderHook } from '@testing-library/react';
import { useMaxStartTime, useShouldAnimate } from '..';
import { FlowLog } from '@/types/render';

const flowLog = {
    id: '1',
    start_time: new Date(1),
} as FlowLog;
const flowLogs = [flowLog] as FlowLog[];

describe('useMaxStartTime', () => {
    it('should return the max value', () => {
        const { rerender, result } = renderHook(
            ({ flowLogs }) => useMaxStartTime(flowLogs),
            { initialProps: { flowLogs } },
        );

        expect(result.current.current).toEqual(
            flowLogs[0].start_time.getTime(),
        );

        const newFlow = {
            id: '2',
            start_time: new Date(),
        } as FlowLog;

        rerender({ flowLogs: [newFlow, ...flowLogs] });

        expect(result.current.current).toEqual(newFlow.start_time.getTime());
    });

    it('should handle an empty array', () => {
        const { rerender, result } = renderHook(
            ({ flowLogs }) => useMaxStartTime(flowLogs),
            { initialProps: { flowLogs: [] as FlowLog[] } },
        );

        expect(result.current.current).toEqual(0);

        rerender({ flowLogs });

        expect(result.current.current).toEqual(
            flowLogs[0].start_time.getTime(),
        );
    });
});

describe('useShouldAnimate', () => {
    const customRenderHook = () =>
        renderHook(
            ({ maxStartTime, flowLogs }) =>
                useShouldAnimate(maxStartTime, flowLogs),
            { initialProps: { maxStartTime: 0, flowLogs: [] as FlowLog[] } },
        );

    it('should return true when the start time is greater than the max', () => {
        const { rerender, result } = customRenderHook();

        const shouldAnimate = result.current;

        rerender({ maxStartTime: 0, flowLogs });

        expect(shouldAnimate(flowLog)).toEqual(true);
        expect(shouldAnimate(flowLog)).toEqual(false);
    });

    it('should return false when the flow has called shouldAnimate already', () => {
        const { rerender, result } = customRenderHook();

        const shouldAnimate = result.current;

        rerender({ maxStartTime: 0, flowLogs });

        expect(shouldAnimate(flowLog)).toEqual(true);
    });

    it('should return false when the flow start time is less than the max time', () => {
        const { result } = renderHook(() => useShouldAnimate(100, flowLogs));

        const shouldAnimate = result.current;

        expect(shouldAnimate(flowLog)).toEqual(false);
    });
});
