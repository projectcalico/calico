import { PopoverContent, PopoverContentProps } from '@chakra-ui/react';
import { forwardRef } from 'react';
import { useStyles } from '../OmniFilterContainer';

const OmniFilterContent = forwardRef<
    HTMLElement,
    PopoverContentProps & { children?: React.ReactNode }
>((props, ref) => {
    const styles = useStyles();

    return (
        <PopoverContent
            ref={ref}
            {...(styles.content as PopoverContentProps)}
            {...props}
        />
    );
});

export default OmniFilterContent;
