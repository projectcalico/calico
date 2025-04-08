import { useAppConfig } from '@/context/AppConfig';

export const useNotifications = () => {
    const notifications = useAppConfig()?.config.notifications;

    return {
        notificationsEnabled: notifications === 'Enabled',
        notificationsDisabled: notifications === 'Disabled',
    };
};
