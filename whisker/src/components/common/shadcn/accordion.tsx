import * as React from 'react';
import * as AccordionPrimitive from '@radix-ui/react-accordion';
import { ChevronDown } from 'lucide-react';

import { cn } from '@/utils/styles';

const Accordion = ({
    className,
    ...props
}: React.ComponentProps<typeof AccordionPrimitive.Root>) => {
    return (
        <AccordionPrimitive.Root
            data-slot='accordion'
            className={cn('flex w-full flex-col', className)}
            data-testid='accordion-root'
            {...props}
        />
    );
};

const AccordionItem = React.forwardRef<
    React.ElementRef<typeof AccordionPrimitive.Item>,
    React.ComponentPropsWithoutRef<typeof AccordionPrimitive.Item>
>(({ className, ...props }, ref) => (
    <AccordionPrimitive.Item
        ref={ref}
        className={cn(
            'border-b! border-tigera-token-border-default! p-0',
            className,
        )}
        data-testid='accordion-item'
        {...props}
    />
));
AccordionItem.displayName = 'AccordionItem';

const AccordionTrigger = React.forwardRef<
    React.ElementRef<typeof AccordionPrimitive.Trigger>,
    React.ComponentPropsWithoutRef<typeof AccordionPrimitive.Trigger>
>(({ className, children, ...props }, ref) => (
    <AccordionPrimitive.Header className='flex'>
        <AccordionPrimitive.Trigger
            ref={ref}
            className={cn(
                'flex! flex-1! items-center! justify-between! px-4! py-2! text-sm! font-medium! transition-all! text-left! bg-tigera-token-bg-neutral-subtle! hover:bg-tigera-token-bg-neutral-subtle-hovered! active:bg-tigera-token-bg-neutral-subtle-pressed! [&[data-state=open]>svg]:rotate-180!',
                className,
            )}
            data-testid='accordion-trigger'
            {...props}
        >
            <ChevronDown className='h-4 w-4 shrink-0 text-muted-foreground transition-transform duration-200 mr-2!' />
            {children}
        </AccordionPrimitive.Trigger>
    </AccordionPrimitive.Header>
));
AccordionTrigger.displayName = AccordionPrimitive.Trigger.displayName;

const AccordionContent = React.forwardRef<
    React.ElementRef<typeof AccordionPrimitive.Content>,
    React.ComponentPropsWithoutRef<typeof AccordionPrimitive.Content>
>(({ className, children, ...props }, ref) => (
    <AccordionPrimitive.Content
        ref={ref}
        className='overflow-hidden data-[state=open]:overflow-visible text-sm data-[state=closed]:animate-accordion-up data-[state=open]:animate-accordion-down mt-4'
        data-testid='accordion-content'
        {...props}
    >
        <div className={cn('pb-4 pt-0', className)}>{children}</div>
    </AccordionPrimitive.Content>
));
AccordionContent.displayName = AccordionPrimitive.Content.displayName;

export { Accordion, AccordionItem, AccordionTrigger, AccordionContent };
