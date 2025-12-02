import * as TabsPrimitive from '@radix-ui/react-tabs';
import { cva } from 'class-variance-authority';
import { useTabsVariant } from '..';

const variants = cva(
    'focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:outline-ring dark:data-[state=active]:border-input flex',
    {
        variants: {
            variant: {
                vertical:
                    'data-[state=active]:!border-tigera-semantic-accent-primary !text-foreground hover:!bg-tigera-white/5 justify-start rounded-none !border-l-2 !border-transparent !bg-transparent !py-2 !pl-2 !text-sm !font-normal transition-all duration-100 data-[state=active]:!bg-tigera-semantic-accent-primary/8 data-[state=active]:hover:!bg-tigera-semantic-accent-primary/12',
            },
        },
    },
);

export default function TabsTrigger({
    className,
    ...props
}: React.ComponentProps<typeof TabsPrimitive.Trigger>) {
    const variant = useTabsVariant();

    return (
        <TabsPrimitive.Trigger
            data-slot='tabs-trigger'
            className={variants({ variant, className })}
            {...props}
        />
    );
}
