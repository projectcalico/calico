import { PopoverHeader, PopoverHeaderProps } from '@chakra-ui/react';
import React from 'react';

type OmniFilterHeaderProps = PopoverHeaderProps & {
    testId: string;
};
export const OmniFilterHeader: React.FC<OmniFilterHeaderProps> = ({
    testId,
    children,
    ...rest
}) => (
    <PopoverHeader
        data-testid={`${testId}-popover-header`}
        borderColor='tigeraGrey.200'
        {...rest}
    >
        {children}
    </PopoverHeader>
);

export default OmniFilterHeader;
