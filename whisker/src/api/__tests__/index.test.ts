import { renderHook } from '@testing-library/react';
import api, { apiFetch, useStream } from '..';
import fetchMock from 'jest-fetch-mock';
import { createEventSource } from '@/utils';
import { act } from 'react';

describe('apiFetch', () => {
    it('should return the expected data', async () => {
        const data = ['foo'];
        fetchMock.mockResolvedValue({
            json: () => Promise.resolve(data),
            ok: true,
        } as any);

        const response = await apiFetch('mock-path', {
            queryParams: { foo: 'bar', key: 'value' },
        });

        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/mock-path?foo=bar&key=value'),
            {},
        );
        expect(response).toEqual(data);
    });

    it('should handle an error response', async () => {
        const error = { message: 'error' };
        const apiResponse = {
            json: () => Promise.resolve(error),
            ok: false,
        } as any;
        fetchMock.mockResolvedValue(apiResponse);

        try {
            await apiFetch('path');
        } catch (thrownError) {
            expect(thrownError).toEqual({
                data: error,
                response: apiResponse,
            } as any);
        }
    });

    it('should handle an error thrown by fetch', async () => {
        fetchMock.mockRejectedValue('fetch error');

        try {
            await apiFetch('path');
        } catch (thrownError) {
            expect(thrownError).toEqual({} as any);
        }
    });
});

describe('api.get', () => {
    it('should call fetch with the correct path', async () => {
        const path = 'custom-path';
        fetchMock.mockResolvedValue({
            json: () => Promise.resolve({}),
            ok: true,
        } as any);

        await api.get(path);

        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining(`/${path}`),
            { method: 'get' },
        );
    });
});

jest.mock('@/utils', () => ({
    createEventSource: jest.fn(),
}));

describe('useStream', () => {
    type Stream = { color: string };
    type TransformedStream = Stream & { id: string };
    const defaultProps = {
        path: '',
        transformResponse: jest.fn(),
    };
    const mockEventSource = {
        onmessage: jest.fn(),
        onerror: jest.fn(),
        onopen: jest.fn(),
        close: jest.fn(),
    };

    beforeEach(() => {
        jest.resetAllMocks();
        jest.mocked(createEventSource).mockReturnValue(mockEventSource as any);
    });

    it('should return the expected default data', () => {
        const { result } = renderHook(() => useStream(defaultProps));

        expect(result.current).toEqual({
            data: [],
            error: null,
            startStream: expect.anything(),
            stopStream: expect.anything(),
            isDataStreaming: false,
            hasStoppedStreaming: false,
            isWaiting: false,
            isFetching: false,
            totalItems: 0,
        });
    });

    it('should call onclose on unmount', () => {
        const { unmount } = renderHook(() => useStream(defaultProps));

        unmount();

        expect(mockEventSource.close).toHaveBeenCalled();
    });

    it('should set data when onmessage is called', async () => {
        jest.useFakeTimers();
        const { result, rerender } = renderHook(() =>
            useStream<Stream, TransformedStream>({
                path: '',
                transformResponse: (stream) => ({ ...stream, id: '1' }),
            }),
        );

        act(() =>
            mockEventSource.onmessage({
                data: JSON.stringify({ color: 'yellow' }),
            }),
        );

        jest.advanceTimersByTime(1000);

        rerender();

        expect(result.current).toEqual({
            data: [{ color: 'yellow', id: expect.any(String) }],
            error: null,
            startStream: expect.anything(),
            stopStream: expect.anything(),
            isDataStreaming: true,
            hasStoppedStreaming: false,
            isWaiting: false,
            isFetching: false,
            totalItems: 1,
        });
    });

    it('should set data when onerror is called', () => {
        const { result, rerender } = renderHook(() => useStream(defaultProps));

        mockEventSource.onerror({ data: JSON.stringify({ color: 'yellow' }) });

        rerender();

        expect(result.current).toEqual({
            data: [],
            error: {},
            startStream: expect.anything(),
            stopStream: expect.anything(),
            isDataStreaming: false,
            hasStoppedStreaming: false,
            isWaiting: false,
            isFetching: false,
            totalItems: 0,
        });

        expect(mockEventSource.close).toHaveBeenCalled();
    });

    it('should be in a waiting state after the stream opens', () => {
        const { result, rerender } = renderHook(() => useStream(defaultProps));

        mockEventSource.onopen({ data: JSON.stringify({ color: 'yellow' }) });

        rerender();

        expect(result.current).toEqual({
            data: [],
            error: null,
            startStream: expect.anything(),
            stopStream: expect.anything(),
            isDataStreaming: false,
            hasStoppedStreaming: false,
            isWaiting: true,
            isFetching: false,
            totalItems: 0,
        });
    });

    it('should call startStream', () => {
        const { result } = renderHook(() => useStream(defaultProps));

        result.current.startStream();

        expect(mockEventSource.close).toHaveBeenCalled();
        expect(createEventSource).toHaveBeenCalledTimes(2);
    });

    it('should call startStream with an updated path', () => {
        const newPath = 'new-path';
        const { result } = renderHook(() => useStream(defaultProps));

        result.current.startStream({ path: newPath });

        expect(createEventSource).toHaveBeenCalledWith(newPath);
    });

    it('should call startStream and replace the existing stream', async () => {
        jest.useFakeTimers();
        jest.mocked(createEventSource).mockReturnValue(mockEventSource as any);
        const { result, rerender } = renderHook(() =>
            useStream<Stream, any>({
                path: '',
                transformResponse: (stream) => stream,
            }),
        );

        act(() =>
            mockEventSource.onmessage({
                data: JSON.stringify({ color: 'yellow' }),
            }),
        );

        jest.advanceTimersByTime(1000);

        rerender();

        result.current.startStream({ path: '', isUpdate: true });

        act(() =>
            mockEventSource.onmessage({
                data: JSON.stringify({ color: 'blue' }),
            }),
        );

        jest.advanceTimersByTime(1000);

        rerender();

        expect(result.current).toEqual({
            data: [{ color: 'blue' }],
            error: null,
            startStream: expect.anything(),
            stopStream: expect.anything(),
            isDataStreaming: true,
            hasStoppedStreaming: false,
            isWaiting: false,
            isFetching: false,
            totalItems: 1,
        });
    });
});
