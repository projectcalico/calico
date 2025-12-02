import * as React from 'react';
import * as TabsPrimitive from '@radix-ui/react-tabs';
import TabsTrigger from './TabsTrigger';
import VariantProvider, { useVariant } from '@/context/VariantProvider';
import TabsList from './TabsList';
import TabsContent from './TabsContent';
import { cva } from 'class-variance-authority';

export type TabsVariant = 'vertical';

export const useTabsVariant = (): TabsVariant => useVariant<TabsVariant>();

const variants = cva('flex flex-col', {
    variants: {
        variant: {
            vertical: 'gap-4 p-4 flex-row',
        },
    },
});

const orientations: Record<TabsVariant, 'vertical' | 'horizontal'> = {
    vertical: 'vertical',
};

function Tabs({
    className,
    children,
    variant,
    ...props
}: React.ComponentProps<typeof TabsPrimitive.Root> & {
    variant: TabsVariant;
}) {
    return (
        <TabsPrimitive.Root
            data-slot='tabs'
            className={variants({ variant, className })}
            orientation={orientations[variant] ?? 'horizontal'}
            {...props}
        >
            <VariantProvider variant={variant}>{children}</VariantProvider>
        </TabsPrimitive.Root>
    );
}

export { Tabs, TabsList, TabsTrigger, TabsContent };
