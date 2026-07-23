import { PopoverBody, PopoverBodyProps } from '@chakra-ui/react';
import React from 'react';
import { useStyles } from '../OmniFilterContainer';

const OmniFilterBody: React.FC<PopoverBodyProps> = ({ children, ...rest }) => {
    const styles = useStyles();

    return (
        <PopoverBody {...(styles.body as PopoverBodyProps)} {...rest}>
            {children}
        </PopoverBody>
    );
};

export default OmniFilterBody;
