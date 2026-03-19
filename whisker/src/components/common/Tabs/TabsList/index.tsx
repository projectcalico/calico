import * as TabsPrimitive from '@radix-ui/react-tabs';
import { cva } from 'class-variance-authority';
import { useTabsVariant } from '..';

const variants = cva('flex flex-row', {
    variants: {
        variant: {
            vertical:
                '!flex-col rounded-none !bg-transparent flex-1 inline-flex !border-r-1 pr-4',
        },
    },
});

export default function TabsList({
    className,
    ...props
}: React.ComponentProps<typeof TabsPrimitive.List>) {
    const variant = useTabsVariant();

    return (
        <TabsPrimitive.List
            data-slot='tabs-list'
            className={variants({ variant, className })}
            {...props}
        />
    );
}
