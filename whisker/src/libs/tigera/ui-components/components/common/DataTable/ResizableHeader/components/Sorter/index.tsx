import * as React from 'react';
import { Box } from '@chakra-ui/react';
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
}) => (
    <Box
        as={
            !isActive
                ? TableSortIcon
                : isDescending
                  ? TableSortIcon
                  : TableAscendingSortIcon
        }
        sx={{
            fill: isActive
                ? 'experimental-token-bg-brand-accent'
                : 'experimental-color-neutral.300',
            marginLeft: '4px',
            ...(!isActive && { transform: 'scaleY(1)' }),
        }}
    />
);

export default Sorter;
