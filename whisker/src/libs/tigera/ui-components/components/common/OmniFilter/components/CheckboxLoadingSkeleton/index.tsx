import {
    Flex,
    FlexProps,
    Skeleton,
    useMultiStyleConfig,
} from '@chakra-ui/react';
import React from 'react';

import { useStyleConfig } from '@chakra-ui/react';

type CheckboxListLoadingSkeletonProps = {
    numberOfLines: number;
} & FlexProps;

export const CheckboxListLoadingSkeleton: React.FC<
    CheckboxListLoadingSkeletonProps
> = ({ numberOfLines, ...rest }) => {
    const styles = useStyleConfig('CheckboxListLoadingSkeleton', rest);

    return (
        <Flex __css={styles} {...rest}>
            {Array.from({ length: numberOfLines }).map((_, index) => (
                <CheckboxLoadingSkeleton key={index} />
            ))}
        </Flex>
    );
};

type CheckboxLoadingSkeletonProps = {} & FlexProps;

const CheckboxLoadingSkeleton: React.FC<CheckboxLoadingSkeletonProps> = ({
    ...rest
}) => {
    const componentStyles = useMultiStyleConfig(
        'CheckboxLoadingSkeleton',
        rest,
    );

    return (
        <Flex sx={componentStyles.container} {...rest}>
            <Skeleton sx={componentStyles.checkbox} />
            <Skeleton sx={componentStyles.label} />
        </Flex>
    );
};

export default CheckboxLoadingSkeleton;
