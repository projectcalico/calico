import { PopoverBody, PopoverBodyProps } from '@chakra-ui/react';
import React from 'react';

type OmniFilterBodyProps = PopoverBodyProps & {
    testId: string;
};

const OmniFilterBody: React.FC<
    React.PropsWithChildren<OmniFilterBodyProps>
> = ({ testId, children, ...rest }) => (
    <PopoverBody data-testid={`${testId}-popover-body`} py={0} {...rest}>
        {children}
    </PopoverBody>
);

export default OmniFilterBody;
