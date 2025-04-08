import { useAppConfig } from '@/context/AppConfig';

export const useNotificationsEnabled = () =>
    useAppConfig()?.config.notifications === 'Enabled';
