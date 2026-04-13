import React from 'react';
import { renderHook } from '@testing-library/react';
import { render, screen } from '@/test-utils/helper';
import VariantProvider, { useVariant, VariantContext } from '../index';

describe('<VariantProvider />', () => {
    it('provides the variant value to children via useVariant hook', () => {
        const TestComponent = () => {
            const variant = useVariant();
            return <div data-testid='variant-display'>{variant}</div>;
        };

        render(
            <VariantProvider variant='custom-variant'>
                <TestComponent />
            </VariantProvider>,
        );

        expect(screen.getByTestId('variant-display')).toHaveTextContent(
            'custom-variant',
        );
    });

    it('provides different variant values correctly', () => {
        const TestComponent = () => {
            const variant = React.useContext(VariantContext);
            return <div data-testid='variant-display'>{variant}</div>;
        };

        const { rerender } = render(
            <VariantProvider variant='variant-1'>
                <TestComponent />
            </VariantProvider>,
        );

        expect(screen.getByTestId('variant-display')).toHaveTextContent(
            'variant-1',
        );

        rerender(
            <VariantProvider variant='variant-2'>
                <TestComponent />
            </VariantProvider>,
        );

        expect(screen.getByTestId('variant-display')).toHaveTextContent(
            'variant-2',
        );
    });

    it('returns the correct variant value when using useVariant hook with renderHook', () => {
        const wrapper = ({ children }: { children: React.ReactNode }) => (
            <VariantProvider variant='test-variant'>{children}</VariantProvider>
        );

        const { result } = renderHook(() => useVariant(), { wrapper });

        expect(result.current).toBe('test-variant');
    });

    it('uses the default variant value when no variant is provided', () => {
        const wrapper = ({ children }: { children: React.ReactNode }) => (
            <VariantProvider>{children}</VariantProvider>
        );
        const { result } = renderHook(() => useVariant(), { wrapper });

        expect(result.current).toBe('default');
    });
});
