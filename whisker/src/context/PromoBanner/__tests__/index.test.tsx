import React from 'react';
import { act, renderHook } from '@/test-utils/helper';
import PromoBannerProvider, { usePromoBanner } from '../index';

describe('usePromoBanner', () => {
    it('throws an error when used outside of the provider', () => {
        const consoleErrorMock = jest
            .spyOn(console, 'error')
            .mockImplementation(() => undefined);

        expect(() => renderHook(() => usePromoBanner())).toThrow(
            'Context error',
        );

        consoleErrorMock.mockRestore();
    });

    it('shows and hides the banner via dispatch', () => {
        const wrapper = ({ children }: { children: React.ReactNode }) => (
            <PromoBannerProvider>{children}</PromoBannerProvider>
        );

        const { result } = renderHook(() => usePromoBanner(), { wrapper });

        expect(result.current.state.isVisible).toBe(false);

        act(() => result.current.dispatch({ type: 'show' }));
        expect(result.current.state.isVisible).toBe(true);

        act(() => result.current.dispatch({ type: 'hide' }));
        expect(result.current.state.isVisible).toBe(false);
    });
});
