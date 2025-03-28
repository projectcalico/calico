import * as React from 'react';
import { Tr, Td } from '@chakra-ui/react';
import type { SystemStyleObject, HTMLChakraProps } from '@chakra-ui/react';
import { noResultsStyles } from './styles';

interface NoResultsProps extends HTMLChakraProps<'div'> {
    sx?: SystemStyleObject;
    message: string;
    colSpan: any;
}

const NoResults: React.FC<React.PropsWithChildren<NoResultsProps>> = ({
    message,
    colSpan,
    sx,
    ...rest
}) => {
    return (
        <Tr sx={{ ...noResultsStyles, ...sx }} as='div' {...rest}>
            <Td colSpan={colSpan} as='div'>
                {message}
            </Td>
        </Tr>
    );
};

export default NoResults;
