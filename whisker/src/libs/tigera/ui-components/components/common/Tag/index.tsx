import * as React from 'react';
import { Tag as ChakraTag, TagProps } from '@chakra-ui/react';
import { inactiveStyles } from './styles';

const Tag: React.FC<
    React.PropsWithChildren<TagProps & { isActive?: boolean }>
> = ({ isActive = true, sx, ...rest }) => {
    return (
        <ChakraTag
            sx={{ ...(!isActive ? inactiveStyles : {}), ...sx }}
            {...rest}
        />
    );
};

export default Tag;
