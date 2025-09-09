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
                {...containerStyles}
                {...partsProps?.container}
            >
                <HStack gap={1} flexWrap='wrap' flex='1 1 0%' py={1}>
                    {options.length === 0 ? (
                        <Text
                            data-testid='select-placeholder'
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
                            />
                        ))
                    )}
                </HStack>
                <IconButton
                    icon={<ChevronDownIcon {...iconStyles} />}
                    variant='ghost'
                    aria-label={''}
                    {...iconButtonStyles}
                />
            </Box>
        </PopoverTrigger>
    );
};

export default OmniTagListTrigger;
