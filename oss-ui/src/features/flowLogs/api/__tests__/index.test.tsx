import api from '@/api';
import { useDeniedFlowLogsCount, useFlowLogs } from '..';
import { renderHookWithQueryClient, waitFor } from '@/test-utils/helper';

jest.mock('@/api', () => ({
    get: jest.fn().mockReturnValue([]),
}));

describe('useFlowLogs', () => {
    it('should call api get with the expected params', () => {
        renderHookWithQueryClient(useFlowLogs);

        expect(api.get).toHaveBeenCalledWith('flow-logs', {
            queryParams: undefined,
        });
    });
});

describe('useDeniedFlowLogsCount', () => {
    it('should return the count of denied flow logs', async () => {
        jest.mocked(api.get).mockResolvedValueOnce(['foo', 'bar']);

        const { result } = renderHookWithQueryClient(useDeniedFlowLogsCount);

        await waitFor(() => expect(result.current).toEqual(2));
    });
});
