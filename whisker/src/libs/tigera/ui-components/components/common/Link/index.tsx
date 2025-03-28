import * as React from 'react';
import { Link as ReactRouterLink } from 'react-router-dom';
import { Link as ChakraLink, LinkProps, forwardRef } from '@chakra-ui/react';

const Link: React.FC<React.PropsWithChildren<LinkProps & { to?: string }>> =
    forwardRef(({ href, to, ...rest }, ref) => (
        <ChakraLink
            ref={ref}
            {...(href && { href })}
            {...(to && { as: ReactRouterLink, to })}
            tabIndex={0}
            {...rest}
        />
    ));

export default Link;
