import React, { ComponentType } from 'react';
import {
    Box,
    Button,
    Checkbox,
    Flex,
    Text,
    forwardRef,
} from '@chakra-ui/react';
import {
    checkboxStyles,
    listItemStyles,
    selectedOptionsListStyles,
    selectedOptionsHeadingStyles,
} from './styles';
import { FixedSizeList, FixedSizeListProps } from 'react-window';
import { OmniFilterOption, OmniInternalListComponentProps } from '../../types';

const List = FixedSizeList as unknown as ComponentType<FixedSizeListProps>;

export type OmniCheckboxListProps = {
    listItemHeight?: number;
    DescriptionComponent?: React.FC<{ data: any }>;
} & OmniInternalListComponentProps;

const LIST_ITEM_HEIGHT = 32;
const MAX_VISIBLE_ITEMS = 9;
const MAX_LIST_HEIGHT = LIST_ITEM_HEIGHT * MAX_VISIBLE_ITEMS;

const CheckBoxListItem: React.FC<{
    isChecked: boolean;
    option: OmniFilterOption;
    index: number;
    DescriptionComponent?: React.FC<{ data: any }>;
    onCheck: (event: any) => void;
}> = forwardRef(
    (
        { isChecked, option, onCheck, index, DescriptionComponent, ...rest },
        ref,
    ) => (
        <Checkbox
            {...checkboxStyles}
            isChecked={isChecked}
            onChange={(event) => onCheck(event)}
            ref={index === 0 ? ref : undefined}
            {...(DescriptionComponent && {
                alignItems: 'flex-start',
                py: 2,
            })}
            {...rest}
        >
            <Text
                isTruncated
                maxWidth='240px'
                title={option.label}
                {...(DescriptionComponent && {
                    lineHeight: 1,
                    overflowX: 'clip',
                    overflowY: 'visible',
                })}
            >
                {option.label}
            </Text>

            {DescriptionComponent && (
                <DescriptionComponent data={option.data} />
            )}
        </Checkbox>
    ),
);

// replace with checkbox list props
const OmniCheckboxList: React.FC<OmniCheckboxListProps> = forwardRef(
    (
        {
            options = [],
            selectedOptions,
            emptyMessage,
            height,
            labelShowMore,
            labelListHeader,
            labelSelectedListHeader,
            showMoreButton,
            showSelectedList,
            isLoadingMore,
            onRequestMore,
            onChange,
            listItemHeight,
            DescriptionComponent,
            ...rest
        },
        ref,
    ) => {
        const listHeight = Math.min(
            options.length * (listItemHeight ?? LIST_ITEM_HEIGHT),
            height ??
                (listItemHeight && listItemHeight * MAX_VISIBLE_ITEMS) ??
                MAX_LIST_HEIGHT,
        );

        const onCheck = (event: any, option: OmniFilterOption) =>
            onChange(
                event.target.checked
                    ? [...selectedOptions, option]
                    : selectedOptions.filter(
                          (selectedOption) =>
                              selectedOption.value !== option.value,
                      ),
            );

        const isChecked = (option: OmniFilterOption) =>
            selectedOptions.some((selected) => selected.value === option.value);

        const optionsForRender = showSelectedList
            ? options.filter((option) => !isChecked(option))
            : options;

        let selectedOptionsListComponent = null;

        if (showSelectedList && selectedOptions.length) {
            selectedOptionsListComponent = (
                <Box>
                    <Text sx={selectedOptionsHeadingStyles}>
                        {labelSelectedListHeader}
                    </Text>
                    <Box as='ul' sx={selectedOptionsListStyles}>
                        {selectedOptions.map((selectedOption, index) => (
                            <Box
                                as='li'
                                sx={listItemStyles}
                                key={selectedOption.value}
                            >
                                <CheckBoxListItem
                                    option={selectedOption}
                                    index={index}
                                    isChecked={isChecked(selectedOption)}
                                    onCheck={(event) =>
                                        onCheck(event, selectedOption)
                                    }
                                    DescriptionComponent={DescriptionComponent}
                                    {...ref}
                                />
                            </Box>
                        ))}
                    </Box>
                </Box>
            );
        }

        return (
            <>
                {selectedOptionsListComponent}

                {selectedOptionsListComponent && (
                    <Text sx={selectedOptionsHeadingStyles}>
                        {labelListHeader}
                    </Text>
                )}

                {optionsForRender.length ? (
                    <List
                        innerElementType='ul'
                        height={listHeight}
                        itemCount={optionsForRender.length}
                        itemSize={listItemHeight ?? LIST_ITEM_HEIGHT}
                        width={'100%'}
                        {...rest}
                    >
                        {({ index, style }) => (
                            <Box as='li' sx={listItemStyles} style={style}>
                                <CheckBoxListItem
                                    key={optionsForRender[index].value}
                                    option={optionsForRender[index]}
                                    index={index}
                                    isChecked={isChecked(
                                        optionsForRender[index],
                                    )}
                                    onCheck={(event) =>
                                        onCheck(event, optionsForRender[index])
                                    }
                                    DescriptionComponent={DescriptionComponent}
                                    {...ref}
                                />

                                {showMoreButton &&
                                index === optionsForRender.length - 1 ? (
                                    <Box>
                                        <Button
                                            mb={3}
                                            mt={1}
                                            variant='ghost'
                                            fontWeight='semibold'
                                            size='sm'
                                            data-testid='show-more-button'
                                            isLoading={isLoadingMore}
                                            isDisabled={isLoadingMore}
                                            onClick={onRequestMore}
                                        >
                                            {labelShowMore}
                                        </Button>
                                    </Box>
                                ) : null}
                            </Box>
                        )}
                    </List>
                ) : (
                    <Flex height={`${LIST_ITEM_HEIGHT}px`} alignItems='center'>
                        <Text color='tigeraGrey.600' px={3}>
                            {emptyMessage}
                        </Text>
                    </Flex>
                )}
            </>
        );
    },
);

export default OmniCheckboxList;
