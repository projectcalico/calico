import * as TabsPrimitive from '@radix-ui/react-tabs';
import { cva } from 'class-variance-authority';
import { useTabsVariant } from '..';

const variants = cva('', {
    variants: {
        variant: {
            vertical: 'flex-2',
        },
    },
});

export default function TabsContent({
    className,
    ...props
}: React.ComponentProps<typeof TabsPrimitive.Content>) {
    const variant = useTabsVariant();

    return (
        <TabsPrimitive.Content
            data-slot='tabs-content'
            className={variants({ variant, className })}
            {...props}
        />
    );
}
