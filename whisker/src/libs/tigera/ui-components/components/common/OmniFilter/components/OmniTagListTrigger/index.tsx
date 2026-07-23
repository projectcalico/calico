import {
    Box,
    HStack,
    IconButton,
    PopoverTrigger,
    Text,
    BoxProps,
} from '@chakra-ui/react';
import { ChevronDownIcon } from '@chakra-ui/icons';
import { OmniFilterOption } from '../../types';
import { containerStyles, iconButtonStyles, iconStyles } from './styles';
import Tag from '@/components/common/Tag';

export type OmniTagListTriggerPartsProps = {
    container?: BoxProps;
};

type OmniTagListTriggerProps = {
    options: OmniFilterOption[];
    onRemove: (option: OmniFilterOption) => void;
    partsProps?: OmniTagListTriggerPartsProps;
    onOpen: () => void;
};

const OmniTagListTrigger: React.FC<OmniTagListTriggerProps> = ({
    options,
    onRemove,
    partsProps,
    onOpen,
}) => {
    return (
        <PopoverTrigger>
            <Box
                role='menu'
                aria-label='Open Popover'
                onKeyDown={(event) => {
                    if (event.key === 'ArrowDown') {
                        onOpen();
                    }
                }}
                tabIndex={0}
                onClick={onOpen}
                data-testid='omni-tag-list-trigger'
                {...containerStyles}
                {...partsProps?.container}
            >
                <HStack
                    gap={1}
                    flexWrap='wrap'
                    flex='1 1 0%'
                    py={1}
                    data-testid='omni-tag-list-container'
                >
                    {options.length === 0 ? (
                        <Text
                            data-testid='omni-tag-list-placeholder'
                            color='tigeraGrey.400'
                            cursor='default'
                        >
                            Select...
                        </Text>
                    ) : (
                        options.map((option) => (
                            <Tag
                                key={option.value}
                                tag={option}
                                onRemove={onRemove}
                                data-testid='omni-tag-list-tag'
                            />
                        ))
                    )}
                </HStack>
                <IconButton
                    icon={<ChevronDownIcon {...iconStyles} />}
                    variant='ghost'
                    aria-label={''}
                    data-testid='omni-tag-list-icon-button'
                    {...iconButtonStyles}
                />
            </Box>
        </PopoverTrigger>
    );
};

export default OmniTagListTrigger;
