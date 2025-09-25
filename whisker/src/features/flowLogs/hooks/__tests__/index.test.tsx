import { renderHook, act } from '@testing-library/react';
import {
    useFlowLogsHeightOffset,
    useMaxStartTime,
    useShouldAnimate,
    useStoredColumns,
} from '..';
import { FlowLog } from '@/types/render';
import { PromoBannerContext } from '@/context/PromoBanner';
import { getV1Columns, getV2Columns } from '../../utils';

jest.mock('../../utils', () => ({
    ...jest.requireActual('../../utils'),
    getV1Columns: jest.fn(),
    getV2Columns: jest.fn(),
}));

const flowLog = {
    id: '1',
    start_time: new Date(2),
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
    const customRenderHook = (startTime?: number) =>
        renderHook(
            ({ maxStartTime, flowLogs }) =>
                useShouldAnimate(maxStartTime, flowLogs.length),
            {
                initialProps: {
                    maxStartTime: startTime ?? 1,
                    flowLogs: [] as FlowLog[],
                },
            },
        );

    it('should return true when the start time is greater than the max', () => {
        const { rerender, result } = customRenderHook(1);

        rerender({ maxStartTime: 1, flowLogs });

        const shouldAnimate = result.current;

        expect(shouldAnimate(flowLog)).toEqual(true);
        expect(shouldAnimate(flowLog)).toEqual(false);
    });

    it('should return false when the start time is 0', () => {
        const { result } = customRenderHook(0);

        const shouldAnimate = result.current;

        expect(shouldAnimate(flowLog)).toEqual(false);
    });

    it('should return false when the flow has called shouldAnimate already', () => {
        const { rerender, result } = customRenderHook();

        const shouldAnimate = result.current;

        rerender({ maxStartTime: 0, flowLogs });

        expect(shouldAnimate(flowLog)).toEqual(true);
    });

    it('should return false when the flow start time is less than the max time', () => {
        const { result } = renderHook(() =>
            useShouldAnimate(100, flowLogs.length),
        );

        const shouldAnimate = result.current;

        expect(shouldAnimate(flowLog)).toEqual(false);
    });
});

describe('useFlowLogsHeightOffset', () => {
    const createWrapper =
        (isVisible: boolean) =>
        ({ children }: any) => (
            <PromoBannerContext.Provider
                value={{
                    dispatch: jest.fn(),
                    state: { isVisible },
                }}
            >
                <>{children}</>
            </PromoBannerContext.Provider>
        );

    it('should include the banner height', () => {
        const { result } = renderHook(() => useFlowLogsHeightOffset(), {
            wrapper: createWrapper(true),
        });

        expect(result.current).toEqual(185);
    });

    it('should not include the banner height', () => {
        const { result } = renderHook(() => useFlowLogsHeightOffset(), {
            wrapper: createWrapper(false),
        });

        expect(result.current).toEqual(145);
    });
});

describe('useStoredColumns', () => {
    const mockInitialValue = {
        start_time: true,
        end_time: false,
        action: true,
        source_namespace: false,
        source_name: true,
        dest_namespace: false,
        dest_name: false,
        protocol: true,
        dest_port: false,
        reporter: true,
    };

    const mockV1Columns = ['start_time', 'action', 'protocol'];
    const mockV2Columns = {
        start_time: true,
        end_time: false,
        action: true,
        source_namespace: false,
        source_name: true,
        dest_namespace: false,
        dest_name: false,
        protocol: true,
        dest_port: false,
        reporter: true,
    };

    const mockLocalStorage = {
        getItem: jest.fn(),
        setItem: jest.fn(),
        removeItem: jest.fn(),
        clear: jest.fn(),
    };

    beforeEach(() => {
        jest.clearAllMocks();

        mockLocalStorage.getItem.mockReturnValue(null);
        mockLocalStorage.setItem.mockImplementation(() => {});
        mockLocalStorage.removeItem.mockImplementation(() => {});
        mockLocalStorage.clear.mockImplementation(() => {});

        Object.defineProperty(window, 'localStorage', {
            value: mockLocalStorage,
            writable: true,
        });

        jest.mocked(getV1Columns).mockImplementation(() => ({
            start_time: true,
            end_time: false,
            action: true,
            source_namespace: false,
            source_name: false,
            dest_namespace: false,
            dest_name: false,
            protocol: true,
            dest_port: false,
            reporter: true,
        }));

        jest.mocked(getV2Columns).mockImplementation(
            (storedData, _key, initialValue) => {
                return storedData ? JSON.parse(storedData) : initialValue;
            },
        );
    });

    it('should return initial value when no stored data exists', () => {
        mockLocalStorage.getItem.mockReturnValue(null);

        const { result } = renderHook(() => useStoredColumns(mockInitialValue));

        expect(result.current[0]).toEqual(mockInitialValue);
        expect(typeof result.current[1]).toBe('function');
        expect(mockLocalStorage.getItem).toHaveBeenCalledWith(
            'whisker-flow-logs-stream-columns',
        );
        expect(mockLocalStorage.getItem).toHaveBeenCalledWith(
            'whisker-flow-logs-stream-columns-v2',
        );
    });

    it('should migrate V1 columns to V2 format and remove V1 data', () => {
        mockLocalStorage.getItem
            .mockReturnValueOnce(JSON.stringify(mockV1Columns))
            .mockReturnValueOnce(null);

        const { result } = renderHook(() => useStoredColumns(mockInitialValue));

        expect(result.current[0]).toEqual({
            start_time: true,
            end_time: false,
            action: true,
            source_namespace: false,
            source_name: false,
            dest_namespace: false,
            dest_name: false,
            protocol: true,
            dest_port: false,
            reporter: true,
        });

        expect(getV1Columns).toHaveBeenCalledWith(
            JSON.stringify(mockV1Columns),
            'whisker-flow-logs-stream-columns-v2',
        );
    });

    it('should retrieve V2 stored columns correctly', () => {
        mockLocalStorage.getItem
            .mockReturnValueOnce(null)
            .mockReturnValueOnce(JSON.stringify(mockV2Columns));

        const { result } = renderHook(() => useStoredColumns(mockInitialValue));

        expect(result.current[0]).toEqual(mockV2Columns);
    });

    it('should use cache optimization when raw data is unchanged', () => {
        mockLocalStorage.getItem
            .mockReturnValueOnce(null)
            .mockReturnValueOnce(JSON.stringify(mockV2Columns));

        const { result, rerender } = renderHook(() =>
            useStoredColumns(mockInitialValue),
        );

        const firstResult = result.current[0];
        expect(firstResult).toBeDefined();

        rerender();
        expect(result.current[0]).toEqual(firstResult);
    });

    it('should update stored value and localStorage when setValue is called', () => {
        mockLocalStorage.getItem.mockReturnValue(null);

        const { result } = renderHook(() => useStoredColumns(mockInitialValue));

        const newValue = { ...mockInitialValue, end_time: true };

        act(() => {
            result.current[1](newValue);
        });

        expect(result.current[0]).toEqual(newValue);
        expect(mockLocalStorage.setItem).toHaveBeenCalledWith(
            'whisker-flow-logs-stream-columns-v2',
            JSON.stringify(newValue),
        );
    });

    it('should remove from localStorage when setValue is called with undefined', () => {
        mockLocalStorage.getItem
            .mockReturnValueOnce(null)
            .mockReturnValueOnce(JSON.stringify(mockV2Columns));

        const { result } = renderHook(() => useStoredColumns(mockInitialValue));

        act(() => {
            result.current[1](undefined);
        });

        expect(result.current[0]).toEqual(mockInitialValue);
        expect(mockLocalStorage.removeItem).toHaveBeenCalledWith(
            'whisker-flow-logs-stream-columns-v2',
        );
    });

    it('should handle JSON parse errors gracefully and return initial value', () => {
        mockLocalStorage.getItem
            .mockReturnValueOnce(null)
            .mockReturnValueOnce('invalid-json');

        const { result } = renderHook(() => useStoredColumns(mockInitialValue));

        expect(result.current[0]).toEqual(mockInitialValue);
        expect(mockLocalStorage.getItem).toHaveBeenCalledWith(
            'whisker-flow-logs-stream-columns',
        );
        expect(mockLocalStorage.getItem).toHaveBeenCalledWith(
            'whisker-flow-logs-stream-columns-v2',
        );
    });

    it('should handle localStorage errors gracefully in setValue', () => {
        mockLocalStorage.getItem.mockReturnValue(null);

        mockLocalStorage.setItem.mockImplementation(() => {
            throw new Error('Storage quota exceeded');
        });

        const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

        const { result } = renderHook(() => useStoredColumns(mockInitialValue));

        act(() => {
            result.current[1](mockV2Columns);
        });

        expect(consoleSpy).toHaveBeenCalled();
        expect(mockLocalStorage.setItem).toHaveBeenCalledWith(
            'whisker-flow-logs-stream-columns-v2',
            JSON.stringify(mockV2Columns),
        );

        consoleSpy.mockRestore();
    });

    it('should handle column migration for new and removed columns', () => {
        const oldColumns = {
            start_time: true,
            action: true,
            protocol: false,
        };

        mockLocalStorage.getItem
            .mockReturnValueOnce(null)
            .mockReturnValueOnce(JSON.stringify(oldColumns));

        const { result } = renderHook(() => useStoredColumns(mockInitialValue));

        expect(result.current[0]).toEqual(oldColumns);

        expect(getV2Columns).toHaveBeenCalledWith(
            JSON.stringify(oldColumns),
            'whisker-flow-logs-stream-columns-v2',
            mockInitialValue,
        );
    });

    it('should handle multiple setValue calls and state updates correctly', () => {
        mockLocalStorage.getItem.mockReturnValue(null);

        const { result } = renderHook(() => useStoredColumns(mockInitialValue));

        const firstUpdate = { ...mockInitialValue, end_time: true };
        act(() => {
            result.current[1](firstUpdate);
        });
        expect(result.current[0]).toEqual(firstUpdate);

        const secondUpdate = { ...firstUpdate, action: false };
        act(() => {
            result.current[1](secondUpdate);
        });
        expect(result.current[0]).toEqual(secondUpdate);

        expect(mockLocalStorage.setItem).toHaveBeenCalledWith(
            'whisker-flow-logs-stream-columns-v2',
            JSON.stringify(firstUpdate),
        );
        expect(mockLocalStorage.setItem).toHaveBeenCalledWith(
            'whisker-flow-logs-stream-columns-v2',
            JSON.stringify(secondUpdate),
        );
        expect(mockLocalStorage.setItem).toHaveBeenCalledTimes(2);
    });
});
