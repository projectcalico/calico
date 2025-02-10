import { Box } from '@chakra-ui/react';
import type { SystemStyleObject, HTMLChakraProps } from '@chakra-ui/react';
import { tabTitleTextStyles, tagStyles } from './styles';
import Tag from '../Tag';

export interface TabTitleProps extends HTMLChakraProps<'div'> {
    isSelected?: boolean;
    hasNoData: boolean;
    badgeCount?: number;
    title: string;
    sx?: SystemStyleObject;
}

const TabTitle = ({
    isSelected = true,
    hasNoData,
    badgeCount,
    sx,
    title,
    ...rest
}: TabTitleProps) => {
    return (
        <Box
            data-role='tabTitle'
            sx={{ ...tabTitleTextStyles(hasNoData), ...sx }}
            {...rest}
        >
            {title}

            {badgeCount !== undefined && (
                <Tag sx={tagStyles} isActive={isSelected}>
                    {badgeCount}
                </Tag>
            )}
        </Box>
    );
};

export default TabTitle;
