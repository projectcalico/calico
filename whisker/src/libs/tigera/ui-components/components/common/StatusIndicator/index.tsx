import * as React from 'react';
import type { BoxProps, SystemStyleObject } from '@chakra-ui/react';
import { Box, Flex, Text, useStyleConfig } from '@chakra-ui/react';

interface StatusIndicatorProps extends BoxProps {
    size?: string;
    color: string;
    sx?: SystemStyleObject;
    label: string | number;
    labelSx?: SystemStyleObject;
}

const StatusIndicator: React.FC<StatusIndicatorProps> = ({
    color,
    label,
    labelSx,
    ...rest
}) => {
    const indicatorStyles = useStyleConfig('StatusIndicator', rest);

    return (
        <Flex __css={indicatorStyles} {...rest}>
            <Box bgColor={color}></Box>

            <Text sx={labelSx}>{label}</Text>
        </Flex>
    );
};

export default StatusIndicator;
