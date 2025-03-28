import * as React from 'react';
import { Stack, Skeleton, Box } from '@chakra-ui/react';
import type { SystemStyleObject, HTMLChakraProps } from '@chakra-ui/react';

export interface TableSkeletonProps extends HTMLChakraProps<'div'> {
    stacks?: number;
    skeletonsPerStack?: number;
    sx?: SystemStyleObject;
}

const TableSkeleton: React.FC<React.PropsWithChildren<TableSkeletonProps>> = ({
    stacks = 1,
    skeletonsPerStack = 10,
    sx,
    ...rest
}) => {
    return (
        <Box sx={sx} {...rest}>
            <Stack m='0' mb='4'>
                <Skeleton height='40px' />
            </Stack>
            {[...Array(stacks).keys()].map((_e, i) => (
                <Stack mt='4' key={i}>
                    {[...Array(skeletonsPerStack).keys()].map((_e, i) => (
                        <Skeleton key={i} height='20px' />
                    ))}
                </Stack>
            ))}
        </Box>
    );
};

export default TableSkeleton;
