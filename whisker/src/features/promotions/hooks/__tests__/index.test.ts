import { useAppConfig } from '@/context/AppConfig';
import { useNotificationsEnabled } from '..';
import { renderHook } from '@/test-utils/helper';
import { AppConfig } from '@/types/render';

jest.mock('@/context/AppConfig', () => ({ useAppConfig: jest.fn() }));

describe('useNotificationsEnabled', () => {
    it('should return false when app config is undefined', () => {
        jest.mocked(useAppConfig).mockReturnValue(undefined);

        const { result } = renderHook(() => useNotificationsEnabled());

        expect(result.current).toEqual(false);
    });

    it('should return false when app notifications = Disabled', () => {
        jest.mocked(useAppConfig).mockReturnValue({
            config: {
                notifications: 'Disabled',
            },
        } as AppConfig);

        const { result } = renderHook(() => useNotificationsEnabled());

        expect(result.current).toEqual(false);
    });

    it('should return true when app notifications = Enabled', () => {
        jest.mocked(useAppConfig).mockReturnValue({
            config: {
                notifications: 'Enabled',
            },
        } as AppConfig);

        const { result } = renderHook(() => useNotificationsEnabled());

        expect(result.current).toEqual(true);
    });
});
