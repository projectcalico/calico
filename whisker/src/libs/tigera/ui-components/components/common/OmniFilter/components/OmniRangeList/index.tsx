import React, { useEffect, useState } from 'react';
import {
    Flex,
    Text,
    forwardRef,
    NumberInput,
    NumberInputField,
    NumberInputStepper,
    NumberIncrementStepper,
    NumberDecrementStepper,
    Box,
} from '@chakra-ui/react';
import { OmniFilterOption, OmniInternalListComponentProps } from '../../types';
import { cloneDeep, debounce, isEqual } from 'lodash';
import { listContainerStyles } from './styles';

// this component expects it 'options' prop to contain 1 or 2 items with the following shape
// (where only 'label' can be customized)
// { label: 'CUSTOM LABEL 1', value: 'gte' },
// { label: 'CUSTOM LABEL 2', value: 'lte' },

const GTE_KEY = 'gte';
const LTE_KEY = 'lte';

interface OmniRangeListProps {
    min?: number;
    max?: number;
    precision?: number;
    step?: number;
}

const OmniRangeList: React.FC<
    OmniInternalListComponentProps & OmniRangeListProps
> = forwardRef(
    (
        {
            options = [],
            onChange,
            selectedOptions,
            min = 0,
            max = 100,
            precision = 0,
            step = 10,
        },
        ref,
    ) => {
        const applyStepChange = debounce(() => {
            // delay on steppers as it ensures any potential onBlur execution to perform *first* on the NumberInputField
            setTimeout(() => {
                setChangeEventPending(true);
            }, 100);
        }, 1000);

        const [localSelectedOptions, setLocalSelectedOptions] = useState<
            OmniFilterOption[]
        >([]);

        const [isChangeEventPending, setChangeEventPending] =
            useState<boolean>(false);

        useEffect(() => {
            if (
                !(
                    options.length <= 2 &&
                    (options.find((option) =>
                        option.value.startsWith(GTE_KEY),
                    ) ||
                        options.find((option) =>
                            option.value.startsWith(LTE_KEY),
                        ))
                )
            ) {
                console.error('OmniRangeList configured incorrectly');
            }
        }, []);

        useEffect(() => {
            // copy and sanitize selectedOptions
            setLocalSelectedOptions([
                ...selectedOptions.filter(
                    (options) =>
                        options.value.startsWith(GTE_KEY) ||
                        options.value.startsWith(LTE_KEY),
                ),
            ]);
        }, [selectedOptions]);

        const validate = (localSelectedOptions: OmniFilterOption[]) => {
            let gteValue: number | null = null;
            let lteValue: number | null = null;

            const isValid = localSelectedOptions.every((option) => {
                const [prefix, value] = option.value.split(':');
                const numericValue = value === '' ? null : parseFloat(value);

                if (
                    numericValue !== null &&
                    (isNaN(numericValue) ||
                        numericValue < min ||
                        numericValue > max)
                ) {
                    return false; // out of bounds
                }

                if (prefix === GTE_KEY) {
                    gteValue = numericValue;
                } else if (prefix === LTE_KEY) {
                    lteValue = numericValue;
                }

                return true;
            });

            // gte cannot be greater than lte
            if (gteValue !== null && lteValue !== null && gteValue > lteValue) {
                return false;
            }

            return isValid;
        };

        useEffect(() => {
            if (isChangeEventPending) {
                if (
                    // aka if changed and valid
                    !isEqual(selectedOptions, localSelectedOptions) &&
                    validate(localSelectedOptions)
                ) {
                    onChange(localSelectedOptions);
                }
                setChangeEventPending(false);
            }
        }, [isChangeEventPending, localSelectedOptions]);

        return (
            <Box data-testid='omni-range-list' sx={listContainerStyles}>
                {options.map((option, index) => {
                    const selected = localSelectedOptions.find(
                        (selectedOption) =>
                            selectedOption.value.startsWith(option.value),
                    );

                    const [_, selectedValue] = (selected?.value || '').split(
                        ':',
                    );

                    return (
                        <Flex
                            key={option.value.split(':')[0]}
                            gap={4}
                            mb={4}
                            alignItems='center'
                            justifyContent={'space-around'}
                        >
                            <Text fontWeight={500}>{option.label}</Text>

                            <NumberInput
                                isInvalid={!validate(localSelectedOptions)}
                                maxWidth='180px'
                                value={
                                    isNaN(parseInt(selectedValue, 10))
                                        ? ''
                                        : selectedValue
                                }
                                precision={precision}
                                min={min}
                                max={max}
                                step={step}
                                clampValueOnBlur={false}
                                onChange={(originalValue: string) => {
                                    // replace any non-digit characters with an empty string
                                    const value = originalValue.replace(
                                        /[^0-9]/g,
                                        '',
                                    );

                                    const [prefix] = option.value.split(':');

                                    const changedOptions = cloneDeep(
                                        localSelectedOptions || [],
                                    );

                                    if (value === '') {
                                        // remove when cleared from field
                                        setLocalSelectedOptions(
                                            changedOptions.filter(
                                                (option) =>
                                                    option.value.split(
                                                        ':',
                                                    )[0] !== prefix,
                                            ),
                                        );
                                    } else {
                                        const changedOption =
                                            changedOptions.find((option) =>
                                                option.value.startsWith(prefix),
                                            );
                                        if (changedOption) {
                                            changedOption.value = `${prefix}:${value}`;
                                        } else {
                                            changedOptions.push({
                                                label: option.label,
                                                value: `${prefix}:${value}`,
                                            });
                                        }
                                        setLocalSelectedOptions(changedOptions);
                                    }
                                }}
                            >
                                <NumberInputField
                                    ref={index === 0 ? ref : undefined}
                                    type='text'
                                    data-testid={`omni-range-list-input-${option.label}`}
                                    onKeyDown={(event) => {
                                        if (event.key === 'Enter') {
                                            setChangeEventPending(true);
                                        }
                                    }}
                                    onBlur={() => {
                                        if (!isChangeEventPending) {
                                            setChangeEventPending(true);
                                        }
                                    }}
                                />
                                <NumberInputStepper>
                                    <NumberIncrementStepper
                                        onClick={() => applyStepChange()}
                                    />
                                    <NumberDecrementStepper
                                        onClick={() => applyStepChange()}
                                    />
                                </NumberInputStepper>
                            </NumberInput>
                        </Flex>
                    );
                })}
            </Box>
        );
    },
);

export default OmniRangeList;
