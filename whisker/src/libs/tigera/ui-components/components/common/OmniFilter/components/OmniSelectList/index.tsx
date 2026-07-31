import { Box, forwardRef } from '@chakra-ui/react';
import React, { ComponentType } from 'react';
import { FixedSizeList, FixedSizeListProps } from 'react-window';
import { OmniFilterOption, OmniInternalListComponentProps } from '../../types';
import ListEmptyMessage from '../ListEmptyMessage';
import SelectListItem from '../SelectListItem';
import ShowMoreButton from '../ShowMoreButton';
import { listItemStyles } from './styles';

const List = FixedSizeList as unknown as ComponentType<FixedSizeListProps>;

export type OmniSelectListProps = {
    listItemHeight?: number;
    DescriptionComponent?: React.FC<{ data: any }>;
} & OmniInternalListComponentProps;

const LIST_ITEM_HEIGHT = 32;
const MAX_VISIBLE_ITEMS = 9;
const MAX_LIST_HEIGHT = LIST_ITEM_HEIGHT * MAX_VISIBLE_ITEMS;

const OmniSelectList: React.FC<OmniSelectListProps> = forwardRef(
    (
        {
            options = [],
            selectedOptions,
            emptyMessage,
            height,
            labelShowMore,
            showMoreButton,
            isLoadingMore,
            onRequestMore,
            onChange,
            listItemHeight,
            ...rest
        },
        ref,
    ) => {
        const onSelect = (option: OmniFilterOption) => {
            const isAlreadySelected = selectedOptions.some(
                (selected) => selected.value === option.value,
            );
            onChange(isAlreadySelected ? [] : [option]);
        };

        const isSelected = (option: OmniFilterOption) =>
            selectedOptions.some((selected) => selected.value === option.value);

        const listHeight = Math.min(
            options.length * (listItemHeight ?? LIST_ITEM_HEIGHT),
            height ??
                (listItemHeight && listItemHeight * MAX_VISIBLE_ITEMS) ??
                MAX_LIST_HEIGHT,
        );

        return (
            <>
                {options.length > 0 ? (
                    <List
                        innerElementType='ul'
                        height={listHeight}
                        itemCount={options.length}
                        itemSize={listItemHeight ?? LIST_ITEM_HEIGHT}
                        width={'100%'}
                        {...rest}
                    >
                        {({ index, style }) => (
                            <Box as='li' sx={listItemStyles} style={style}>
                                <SelectListItem
                                    key={options[index].value}
                                    option={options[index]}
                                    index={index}
                                    isSelected={isSelected(options[index])}
                                    onSelect={() => onSelect(options[index])}
                                    {...ref}
                                />

                                {showMoreButton &&
                                index === options.length - 1 ? (
                                    <ShowMoreButton
                                        isLoadingMore={isLoadingMore}
                                        onRequestMore={onRequestMore}
                                    >
                                        {labelShowMore}
                                    </ShowMoreButton>
                                ) : null}
                            </Box>
                        )}
                    </List>
                ) : (
                    <ListEmptyMessage height={LIST_ITEM_HEIGHT}>
                        {emptyMessage}
                    </ListEmptyMessage>
                )}
            </>
        );
    },
);

export default OmniSelectList;
