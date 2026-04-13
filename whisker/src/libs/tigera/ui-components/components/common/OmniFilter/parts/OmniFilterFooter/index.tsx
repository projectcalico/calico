import { PopoverFooter, PopoverFooterProps } from '@chakra-ui/react';
import React from 'react';
import { useStyles } from '../OmniFilterContainer';

const OmniFilterFooter: React.FC<PopoverFooterProps> = ({
    children,
    ...rest
}) => {
    const styles = useStyles();

    return (
        <PopoverFooter {...(styles.footer as PopoverFooterProps)} {...rest}>
            {children}
        </PopoverFooter>
    );
};

export default OmniFilterFooter;
