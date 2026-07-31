import { CheckIcon } from '@chakra-ui/icons';
import { Box, Text, forwardRef } from '@chakra-ui/react';
import React from 'react';
import { OmniFilterOption } from '../../types';
import { selectItemStyles } from './styles';

type SelectListItemProps = {
    isSelected: boolean;
    option: OmniFilterOption;
    index: number;
    onSelect: () => void;
};

const SelectListItem: React.FC<SelectListItemProps> = forwardRef(
    ({ isSelected, option, onSelect, index }, ref) => {
        return (
            <Box
                ref={index === 0 ? ref : undefined}
                onClick={onSelect}
                sx={selectItemStyles}
                data-testid='select-list-item'
            >
                <Box
                    width='16px'
                    height='16px'
                    flexShrink={0}
                    display='flex'
                    alignItems='center'
                    justifyContent='center'
                >
                    {isSelected && (
                        <CheckIcon
                            boxSize={3}
                            color='experimental-token-fg-subtle'
                            data-testid='select-list-item-check-icon'
                        />
                    )}
                </Box>

                <Box flex={1} minWidth={0}>
                    <Text
                        isTruncated
                        maxWidth='240px'
                        title={option.label}
                        data-testid='select-list-item-label'
                    >
                        {option.label}
                    </Text>
                </Box>
            </Box>
        );
    },
);

export default SelectListItem;
