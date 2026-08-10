import { useAppConfig } from '@/context/AppConfig';
import { renderHookWithQueryClient, waitFor } from '@/test-utils/helper';
import { usePromotionsContent } from '..';

import fetchMock from 'jest-fetch-mock';
import { BannerContent } from '@/types/api';

jest.mock('@/context/AppConfig', () => ({ useAppConfig: jest.fn() }));

describe('usePromotionsContent', () => {
    it('should return the promotions data', async () => {
        const config = {
            cluster_id: 'cluster-id',
            cluster_type: 'cluster-type',
            calico_version: 'cluster-version',
            calico_cloud_url: 'https://cloud-url/api',
        };
        const response: BannerContent = {
            bannerLink: 'banner-link',
            bannerText: 'banner-text',
        };
        jest.mocked(useAppConfig).mockReturnValue({
            config,
        } as any);
        fetchMock.mockResolvedValue({
            json: () => Promise.resolve(response),
            ok: true,
        } as any);

        const { result } = renderHookWithQueryClient(() =>
            usePromotionsContent(true),
        );

        await waitFor(() => expect(result.current).toEqual(response));
        expect(fetchMock).toHaveBeenCalledWith(
            'https://cloud-url/api/whisker/content',
            expect.objectContaining({
                body: JSON.stringify({
                    id: config.cluster_id,
                    calico_version: config.calico_version,
                    cluster_type: config.cluster_type,
                }),
            }),
        );
    });

    it('should not call fetch when the query is disabled', () => {
        fetchMock.mockClear();

        renderHookWithQueryClient(() => usePromotionsContent(false));

        expect(fetchMock).not.toHaveBeenCalled();
    });

    it('should not call fetch when there is no config', () => {
        fetchMock.mockClear();
        jest.mocked(useAppConfig).mockReturnValue(undefined);

        renderHookWithQueryClient(() => usePromotionsContent(true));

        expect(fetchMock).not.toHaveBeenCalled();
    });

    it('should send fallback values when config properties are missing', async () => {
        fetchMock.mockClear();
        jest.mocked(useAppConfig).mockReturnValue({ config: null } as any);
        fetchMock.mockResolvedValue({
            json: () => Promise.resolve({}),
            ok: true,
        } as any);

        renderHookWithQueryClient(() => usePromotionsContent(true));

        await waitFor(() =>
            expect(fetchMock).toHaveBeenCalledWith(
                'undefined/whisker/content',
                expect.objectContaining({
                    body: JSON.stringify({}),
                }),
            ),
        );
    });
});
