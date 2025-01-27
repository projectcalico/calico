import * as React from 'react';
import { Box, useColorModeValue } from '@chakra-ui/react';
import {
    TableAscendingSortIcon,
    TableSortIcon,
} from '../../../../../../../../../icons';

interface SorterProps {
    isActive: boolean;
    isDescending: boolean;
}

const Sorter: React.FC<React.PropsWithChildren<SorterProps>> = ({
    isActive,
    isDescending,
}) => {
    const activeColor = useColorModeValue(
        'tigeraBlueMedium40',
        'tigeraGoldMedium',
    );
    const inactiveColor = useColorModeValue('tigeraGrey.600', 'tigeraGrey.400');

    return (
        <Box
            as={
                !isActive
                    ? TableSortIcon
                    : isDescending
                      ? TableSortIcon
                      : TableAscendingSortIcon
            }
            fill={isActive ? activeColor : inactiveColor}
            style={{
                marginLeft: '4px',
                ...(!isActive && { transform: 'scaleY(1)' }),
            }}
        />
    );
};

export default Sorter;
