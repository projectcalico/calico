import { renderHook } from '@testing-library/react';
import api, { apiFetch, useStream } from '..';
import fetchMock from 'jest-fetch-mock';
import { createEventSource } from '@/utils';

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
    beforeEach(() => {
        jest.resetAllMocks();
    });
    it('should return the expected default data', () => {
        jest.mocked(createEventSource).mockReturnValue({
            onmessage: jest.fn(),
            onerror: jest.fn(),
            close: jest.fn(),
        } as any);

        const { result } = renderHook(() => useStream(''));

        expect(result.current).toEqual({
            data: [],
            error: null,
            startStream: expect.anything(),
            stopStream: expect.anything(),
            isStreaming: true,
            isFetching: true,
        });
    });

    it('should call onclose on unmount', () => {
        const mockEventSource = {
            onmessage: jest.fn(),
            onerror: jest.fn(),
            close: jest.fn(),
        };
        jest.mocked(createEventSource).mockReturnValue(mockEventSource as any);

        const { unmount } = renderHook(() => useStream(''));

        unmount();

        expect(mockEventSource.close).toHaveBeenCalled();
    });

    it('should set data when onmessage is called', () => {
        const mockEventSource = {
            onmessage: jest.fn(),
            onerror: jest.fn(),
            close: jest.fn(),
        };
        jest.mocked(createEventSource).mockReturnValue(mockEventSource as any);

        const { result, rerender } = renderHook(() => useStream(''));

        mockEventSource.onmessage({
            data: JSON.stringify({ color: 'yellow' }),
        });

        rerender();

        expect(result.current).toEqual({
            data: [{ color: 'yellow' }],
            error: null,
            startStream: expect.anything(),
            stopStream: expect.anything(),
            isStreaming: true,
            isFetching: false,
        });
    });

    it('should set data when onmessage is called', () => {
        const mockEventSource = {
            onmessage: jest.fn(),
            onerror: jest.fn(),
            close: jest.fn(),
        };
        jest.mocked(createEventSource).mockReturnValue(mockEventSource as any);

        const { result, rerender } = renderHook(() => useStream(''));

        mockEventSource.onerror({ data: JSON.stringify({ color: 'yellow' }) });

        rerender();

        expect(result.current).toEqual({
            data: [],
            error: {},
            startStream: expect.anything(),
            stopStream: expect.anything(),
            isStreaming: true,
            isFetching: false,
        });

        expect(mockEventSource.close).toHaveBeenCalled();
    });

    it('should call startStream', () => {
        const mockEventSource = {
            onmessage: jest.fn(),
            onerror: jest.fn(),
            close: jest.fn(),
        };
        jest.mocked(createEventSource).mockReturnValue(mockEventSource as any);

        const { result } = renderHook(() => useStream(''));

        result.current.startStream();

        expect(mockEventSource.close).toHaveBeenCalled();
        expect(createEventSource).toHaveBeenCalledTimes(2);
    });
});
