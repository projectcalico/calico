import { PopoverHeader, PopoverHeaderProps } from '@chakra-ui/react';
import React from 'react';
import { useStyles } from '../OmniFilterContainer';

const OmniFilterHeader: React.FC<PopoverHeaderProps> = ({
    children,
    ...rest
}) => {
    const styles = useStyles();

    return (
        <PopoverHeader {...(styles.header as PopoverHeaderProps)} {...rest}>
            {children}
        </PopoverHeader>
    );
};

export default OmniFilterHeader;
