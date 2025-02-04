import api, { apiFetch } from '..';
import fetchMock from 'jest-fetch-mock';

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
