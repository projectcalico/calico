import { useAppConfig } from '@/context/AppConfig';
import { useNotifications } from '..';
import { renderHook } from '@/test-utils/helper';
import { AppConfig } from '@/types/render';

jest.mock('@/context/AppConfig', () => ({ useAppConfig: jest.fn() }));

describe('useNotificationsEnabled', () => {
    it('should return false when app config is undefined', () => {
        jest.mocked(useAppConfig).mockReturnValue(undefined);

        const { result } = renderHook(() => useNotifications());

        expect(result.current).toEqual({
            notificationsEnabled: false,
            notificationsDisabled: false,
        });
    });

    it('should return false when app notifications = Disabled', () => {
        jest.mocked(useAppConfig).mockReturnValue({
            config: {
                notifications: 'Disabled',
            },
        } as AppConfig);

        const { result } = renderHook(() => useNotifications());

        expect(result.current).toEqual({
            notificationsEnabled: false,
            notificationsDisabled: true,
        });
    });

    it('should return true when app notifications = Enabled', () => {
        jest.mocked(useAppConfig).mockReturnValue({
            config: {
                notifications: 'Enabled',
            },
        } as AppConfig);

        const { result } = renderHook(() => useNotifications());

        expect(result.current).toEqual({
            notificationsEnabled: true,
            notificationsDisabled: false,
        });
    });
});
