import { PopoverFooter, PopoverFooterProps } from '@chakra-ui/react';
import React from 'react';

type OmniFilterFooterProps = PopoverFooterProps & {
    testId: string;
};

export const OmniFilterFooter: React.FC<
    React.PropsWithChildren<OmniFilterFooterProps>
> = ({ testId, children, ...rest }) => (
    <PopoverFooter
        borderColor='tigeraGrey.200'
        data-testid={`${testId}-popover-footer`}
        display='flex'
        {...rest}
    >
        {children}
    </PopoverFooter>
);

export default OmniFilterFooter;
