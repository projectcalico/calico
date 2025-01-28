import * as React from 'react';
import { Box } from '@chakra-ui/react';
import { ChevronRightIcon, ChevronDownIcon } from '@chakra-ui/icons';
import type {
    SystemStyleObject,
    HTMLChakraProps,
    IconProps,
} from '@chakra-ui/react';
import { tableExpandoCellStyles } from './styles';

interface ExpandoCellProps extends HTMLChakraProps<'div'> {
    sx?: SystemStyleObject;
    isExpanded: boolean;
    value: string;
    iconProps?: IconProps;
}

const ExpandoCell = React.forwardRef(
    ({ isExpanded, value, sx, iconProps, ...rest }: ExpandoCellProps, ref) => (
        <Box
            ref={ref as any}
            data-testid={'expando-cell'}
            sx={{ ...tableExpandoCellStyles, ...sx }}
            {...rest}
        >
            {isExpanded ? (
                <ChevronDownIcon w={5} h={5} mr={1} {...iconProps} />
            ) : (
                <ChevronRightIcon w={5} h={5} mr={1} {...iconProps} />
            )}
            {value}
        </Box>
    ),
);

ExpandoCell.displayName = 'ExpandoCell';

export default ExpandoCell;
