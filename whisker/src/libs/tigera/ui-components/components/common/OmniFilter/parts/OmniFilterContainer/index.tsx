import {
    Popover,
    PopoverProps,
    createStylesContext,
    useMultiStyleConfig,
} from '@chakra-ui/react';
import React from 'react';

const [StylesProvider, useStyles] = createStylesContext('OmniFilter');

export { useStyles };

const OmniFilterContainer: React.FC<PopoverProps> = ({ children, ...rest }) => {
    const styles = useMultiStyleConfig('OmniFilter', rest);

    return (
        <StylesProvider value={styles}>
            <Popover
                isLazy
                placement='bottom-start'
                variant='omniFilter'
                {...rest}
            >
                {children}
            </Popover>
        </StylesProvider>
    );
};

export default OmniFilterContainer;
