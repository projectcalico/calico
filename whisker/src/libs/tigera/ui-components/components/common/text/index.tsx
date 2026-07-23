import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/utils/styles';
import { Slot } from '@radix-ui/react-slot';

const textVariants = cva('', {
    variants: {
        variant: {
            default: 'text-base text-tigera-token-fg-default',
        },
        size: {
            xs: 'text-xs leading-tight',
            sm: 'text-sm leading-tight',
            base: 'text-base leading-normal',
            lg: 'text-lg leading-relaxed',
            xl: 'text-xl leading-relaxed',
        },
    },
    defaultVariants: {
        variant: 'default',
        size: 'base',
    },
});

export interface TextProps
    extends React.HTMLAttributes<HTMLParagraphElement>,
        VariantProps<typeof textVariants> {
    asChild?: boolean;
}

const Text = React.forwardRef<HTMLParagraphElement, TextProps>(
    ({ className, variant, size, asChild, ...rest }, ref) => {
        const Comp = asChild ? Slot : 'p';
        return (
            <Comp
                ref={ref}
                className={cn(textVariants({ variant, size }), className)}
                {...rest}
            />
        );
    },
);

Text.displayName = 'Text';

export { Text };
