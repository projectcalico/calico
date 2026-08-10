import { act, renderHook } from '@/test-utils/helper';
import {
    useBuildInfo,
    useClusterId,
    useDebouncedCallback,
    useFeature,
} from '..';
import { useAppConfig } from '@/context/AppConfig';
import { AppConfig } from '@/types/render';

jest.mock('@/context/AppConfig', () => ({ useAppConfig: jest.fn() }));

describe('useDebouncedCallback', () => {
    beforeEach(() => {
        jest.useFakeTimers();
    });

    afterEach(() => {
        jest.useRealTimers();
    });

    it('should call the callback after the debounce time has elapsed', () => {
        const callback = jest.fn();
        const { result } = renderHook(() => useDebouncedCallback());

        act(() => result.current('search', callback));

        act(() => jest.advanceTimersByTime(499));
        expect(callback).not.toHaveBeenCalled();

        act(() => jest.advanceTimersByTime(1));
        expect(callback).toHaveBeenCalledTimes(1);
    });

    it('should do nothing when the timer fires before a callback is registered', () => {
        const callback = jest.fn();
        const { result } = renderHook(() => useDebouncedCallback());

        // the initial timer fires with the default no-op callback
        act(() => jest.advanceTimersByTime(500));
        expect(callback).not.toHaveBeenCalled();

        // registering a callback afterwards still debounces as normal
        act(() => result.current('search', callback));
        act(() => jest.advanceTimersByTime(500));
        expect(callback).toHaveBeenCalledTimes(1);
    });

    it('should clear the pending timer when called again with a new value', () => {
        const firstCallback = jest.fn();
        const secondCallback = jest.fn();
        const { result } = renderHook(() => useDebouncedCallback());

        act(() => result.current('foo', firstCallback));
        act(() => jest.advanceTimersByTime(499));

        act(() => result.current('bar', secondCallback));

        // the first timer would have fired here if it had not been cleared
        act(() => jest.advanceTimersByTime(1));
        expect(firstCallback).not.toHaveBeenCalled();
        expect(secondCallback).not.toHaveBeenCalled();

        act(() => jest.advanceTimersByTime(499));
        expect(firstCallback).not.toHaveBeenCalled();
        expect(secondCallback).toHaveBeenCalledTimes(1);
    });
});

describe('useClusterId', () => {
    it('should return the cluster id from the app config', () => {
        jest.mocked(useAppConfig).mockReturnValue({
            config: { cluster_id: 'test-cluster-id' },
        } as AppConfig);

        const { result } = renderHook(() => useClusterId());

        expect(result.current).toEqual('test-cluster-id');
    });

    it('should return undefined when there is no app config', () => {
        jest.mocked(useAppConfig).mockReturnValue(undefined);

        const { result } = renderHook(() => useClusterId());

        expect(result.current).toBeUndefined();
    });
});

describe('useFeature', () => {
    it('should return true when the feature is enabled', () => {
        jest.mocked(useAppConfig).mockReturnValue({
            features: { my_feature: true },
        } as unknown as AppConfig);

        const { result } = renderHook(() => useFeature('my_feature'));

        expect(result.current).toEqual(true);
    });

    it('should return false when the feature is disabled', () => {
        jest.mocked(useAppConfig).mockReturnValue({
            features: { my_feature: false },
        } as unknown as AppConfig);

        const { result } = renderHook(() => useFeature('my_feature'));

        expect(result.current).toEqual(false);
    });

    it('should return false when there are no features in the app config', () => {
        jest.mocked(useAppConfig).mockReturnValue({} as AppConfig);

        const { result } = renderHook(() => useFeature('my_feature'));

        expect(result.current).toEqual(false);
    });

    it('should return false when there is no app config', () => {
        jest.mocked(useAppConfig).mockReturnValue(undefined);

        const { result } = renderHook(() => useFeature('my_feature'));

        expect(result.current).toEqual(false);
    });
});

describe('useBuildInfo', () => {
    it('should log build information on mount', () => {
        const groupCollapsedMock = jest
            .spyOn(console, 'groupCollapsed')
            .mockImplementation(() => undefined);
        const infoMock = jest
            .spyOn(console, 'info')
            .mockImplementation(() => undefined);
        const groupEndMock = jest
            .spyOn(console, 'groupEnd')
            .mockImplementation(() => undefined);

        renderHook(() => useBuildInfo());

        expect(groupCollapsedMock).toHaveBeenCalledWith('Build information');
        expect(infoMock).toHaveBeenCalledWith(
            expect.stringContaining('version = '),
        );
        expect(groupEndMock).toHaveBeenCalled();

        groupCollapsedMock.mockRestore();
        infoMock.mockRestore();
        groupEndMock.mockRestore();
    });
});
