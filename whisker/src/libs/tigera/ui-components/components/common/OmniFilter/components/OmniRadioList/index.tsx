import React from 'react';
import {
    RadioGroup,
    Radio,
    Flex,
    Text,
    List,
    ListItem,
    forwardRef,
} from '@chakra-ui/react';
import { listItemStyles } from './styles';
import { OmniFilterOption, OmniInternalListComponentProps } from '../../types';

// note: a radio list type will not render a virtualised list, and should only be used for small lists of items

const OmniRadioList: React.FC<OmniInternalListComponentProps> = forwardRef(
    (
        {
            options = [],
            onChange,
            selectedOptions,
            emptyMessage,
            _height,
            _onRequestMore,
            _showMoreButton,
            _labelShowMore,
            ...rest
        },
        ref,
    ) => (
        <>
            {options.length ? (
                <List data-testid='omni-radio-list'>
                    <RadioGroup
                        value={
                            selectedOptions.length
                                ? selectedOptions[0].value
                                : ''
                        }
                        onChange={(value) =>
                            onChange([
                                options.find(
                                    (selectedOption) =>
                                        selectedOption.value === value,
                                ) as OmniFilterOption,
                            ])
                        }
                        {...rest}
                    >
                        {options.map((option, index) => (
                            <ListItem sx={listItemStyles} key={option.value}>
                                <Radio
                                    key={option.value}
                                    mb={0}
                                    py={1}
                                    w='full'
                                    value={option.value}
                                    ref={index === 0 ? ref : undefined}
                                >
                                    <Text
                                        isTruncated
                                        maxWidth='240px'
                                        title={option.label}
                                    >
                                        {option.label}
                                    </Text>
                                </Radio>
                            </ListItem>
                        ))}
                    </RadioGroup>
                </List>
            ) : (
                <Flex alignItems='center'>
                    <Text color='tigeraGrey.600' px={3}>
                        {emptyMessage}
                    </Text>
                </Flex>
            )}
        </>
    ),
);

export default OmniRadioList;
