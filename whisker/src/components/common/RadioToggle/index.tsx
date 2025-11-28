import { Flex, SystemStyleObject, useRadioGroup } from '@chakra-ui/react';
import React from 'react';
import RadioToggleCard from './components/RadioCard';

export type RadioToggleOption = {
    value: string;
    label: string;
    icon?: React.ReactNode;
    styles?: SystemStyleObject;
};

type RadioToggle = {
    value: string | undefined;
    name: string;
    onChange: (value: string) => void;
    options: RadioToggleOption[];
    maxWidth?: string | number;
    containerStyles?: SystemStyleObject;
    testId?: string;
};

const RadioToggleGroup: React.FC<RadioToggle> = ({
    value,
    name,
    onChange,
    options,
    containerStyles,
    testId,
}) => {
    const { getRootProps, getRadioProps } = useRadioGroup({
        name,
        onChange,
        value,
    });

    const group = getRootProps();

    return (
        <Flex {...group} gap={0} sx={containerStyles} data-testid={testId}>
            {options.map((option, index) => (
                <RadioToggleCard
                    key={option.value}
                    isFirst={index === 0}
                    isLast={index === options.length - 1}
                    onClear={() => onChange('')}
                    label={option.label}
                    containerStyles={option.styles || {}}
                    icon={option.icon}
                    {...getRadioProps({ value: option.value })}
                />
            ))}
        </Flex>
    );
};

export default RadioToggleGroup;
