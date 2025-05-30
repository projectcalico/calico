import {
    Flex,
    FlexProps,
    Skeleton,
    useColorModeValue,
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
    const startColor = useColorModeValue('tigeraGrey.50', 'tigeraGrey.1000');
    const endColor = useColorModeValue('tigeraGrey.400', 'tigeraGrey.600');

    return (
        <Flex sx={componentStyles.container} {...rest}>
            <Skeleton
                sx={componentStyles.checkbox}
                startColor={startColor}
                endColor={endColor}
                speed={0.9}
            />
            <Skeleton
                sx={componentStyles.label}
                startColor={startColor}
                endColor={endColor}
                speed={0.9}
            />
        </Flex>
    );
};

export default CheckboxLoadingSkeleton;
