'use client';

import * as React from 'react';
import * as CheckboxPrimitive from '@radix-ui/react-checkbox';
import { CheckIcon } from 'lucide-react';

import { cn } from '@/utils/styles';

function Checkbox({
    className,
    ...props
}: React.ComponentProps<typeof CheckboxPrimitive.Root>) {
    return (
        <CheckboxPrimitive.Root
            data-slot='checkbox'
            className={cn(
                'peer! border-tigera-token-border-default! dark:bg-tigera-token-bg-input/30! data-[state=checked]:bg-tigera-token-bg-brand! data-[state=checked]:text-tigera-token-fg-inverted! dark:data-[state=checked]:bg-tigera-token-bg-brand! data-[state=checked]:border-tigera-token-bg-brand! focus-visible:border-tigera-token-border-bold! focus-visible:ring-tigera-token-border-bold/50! aria-invalid:ring-tigera-token-border-danger/20! dark:aria-invalid:ring-tigera-token-border-danger/40! aria-invalid:border-tigera-token-border-danger! size-4! shrink-0! rounded-[4px]! border! shadow-xs! transition-shadow! outline-none! focus-visible:ring-[3px]! disabled:cursor-not-allowed! disabled:opacity-50!',
                className,
            )}
            {...props}
        >
            <CheckboxPrimitive.Indicator
                data-slot='checkbox-indicator'
                className='grid place-content-center text-current transition-none'
            >
                <CheckIcon className='size-3.5' />
            </CheckboxPrimitive.Indicator>
        </CheckboxPrimitive.Root>
    );
}

export { Checkbox };
