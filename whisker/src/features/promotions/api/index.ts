import { useAppConfig } from '@/context/AppConfig';
import { BannerContent } from '@/types/api';
import { useQuery } from '@tanstack/react-query';

export const usePromotionsContent = (enabled: boolean) => {
    const { config } = useAppConfig() ?? {};
    const { data } = useQuery<BannerContent>({
        enabled: enabled && config !== undefined,
        queryKey: ['promotions-content'],
        queryFn: () =>
            fetch(`${config?.calico_cloud_url}/whisker/content`, {
                method: 'POST',
                headers: {
                    Accept: 'application/json',
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    id: config?.cluster_id,
                    calico_version: config?.calico_version,
                    cluster_type: config?.cluster_type,
                }),
            }).then((response) => response.json()),
    });

    return data;
};
