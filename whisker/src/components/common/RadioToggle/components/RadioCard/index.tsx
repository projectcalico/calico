import { Box, Flex, SystemStyleObject, useRadio } from '@chakra-ui/react';
import React from 'react';
import { checkboxStyles, firstStyles, lastStyles } from './styles';

type RadioCardProps = {
    isFirst: boolean;
    isLast: boolean;
    onClear: () => void;
    label: string;
    icon: React.ReactNode;
    containerStyles: SystemStyleObject;
};

const RadioCard: React.FC<RadioCardProps> = ({
    isFirst,
    isLast,
    onClear,
    label,
    icon,
    containerStyles,
    ...props
}) => {
    const { getInputProps, getRadioProps } = useRadio(props);
    const input = getInputProps();
    const checkbox = getRadioProps();

    return (
        <Box as='label' flex={1}>
            <input {...input} />
            <Flex
                onClick={(event) => {
                    if (input.checked) {
                        event.preventDefault();
                        onClear();
                    }
                }}
                {...checkbox}
                sx={{
                    ...checkboxStyles,
                    ...(isFirst && firstStyles),
                    ...(isLast && lastStyles),
                    ...containerStyles,
                }}
            >
                {icon}
                {label}
            </Flex>
        </Box>
    );
};

export default RadioCard;
