import { PopoverContent, PopoverContentProps } from '@chakra-ui/react';
import React from 'react';
import { useStyles } from '../OmniFilterContainer';

type OmniFilterContentProps = PopoverContentProps & {
    testId: string;
    popoverContentRef: React.RefObject<HTMLElement>;
};
export const OmniFilterContent: React.FC<
    React.PropsWithChildren<OmniFilterContentProps>
> = ({ testId, popoverContentRef, children, ...rest }) => {
    const styles = useStyles();

    return (
        <PopoverContent
            data-testid={`${testId}-popover-content`}
            sx={styles.content}
            ref={popoverContentRef}
            {...rest}
        >
            {children}
        </PopoverContent>
    );
};

export default OmniFilterContent;
