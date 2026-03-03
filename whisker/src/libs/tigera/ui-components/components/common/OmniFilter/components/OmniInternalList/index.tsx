import { AddIcon } from '@chakra-ui/icons';
import { Box, Button, Center, Text, VStack } from '@chakra-ui/react';
import React from 'react';
import { OmniFilterOption, OmniInternalListComponentProps } from '../../types';
import { CheckboxListLoadingSkeleton } from '../CheckboxLoadingSkeleton';
import OmniCheckboxList, { OmniCheckboxListProps } from '../OmniCheckboxList';
import OmniRadioList from '../OmniRadioList';

export type OmniFilterChangeEvent = {
    filterId: string;
    filterLabel: string;
    operator: string | undefined;
    filters: OmniFilterOption[];
};

export type ListType = 'checkbox' | 'radio';

type OmniInternalListProps = {
    options: OmniFilterOption[];
    selectedOptions: OmniFilterOption[];
    filteredSelectedOptions: OmniFilterOption[];
    showSelectedList?: boolean;
    emptyMessage: string;
    showMoreButton: boolean;
    isLoadingMore: boolean;
    labelShowMore?: string;
    height?: number;
    labelListHeader?: string;
    labelSelectedListHeader?: string;
    ref?: React.RefObject<HTMLInputElement>;
    listType: ListType;
    internalListComponentProps?: OmniCheckboxListProps;
    isCreatable: boolean;
    searchInput: string;
    filteredData: OmniFilterOption[];
    selectedFilters: OmniFilterOption[];
    labelNoData: string;
    testId: string;
    isLoading: boolean;
    hasFilters: boolean;
    filterId: string;
    InternalListComponent?: React.ComponentType<OmniInternalListComponentProps>;
    onChange: (options: OmniFilterOption[]) => void;
    onRequestMore?: () => void;
    onRequestSearch?: (filterId: string, searchOption: string) => void;
    formatCreatableLabel?: (searchInput: string) => string;
    onClearSearch: () => void;
};
const OmniInternalList: React.FC<OmniInternalListProps> = ({
    filterId,
    isLoading,
    isLoadingMore,
    testId,
    hasFilters,
    InternalListComponent,
    listType,
    internalListComponentProps,
    isCreatable,
    searchInput,
    filteredData,
    selectedFilters,
    labelNoData,
    onRequestSearch,
    formatCreatableLabel,
    onClearSearch,
    ...listComponentProps
}) => {
    return (
        <>
            {isLoading && !isLoadingMore ? (
                <CheckboxListLoadingSkeleton
                    numberOfLines={8}
                    data-testid={`${testId}-list-skeleton`}
                />
            ) : hasFilters ? (
                InternalListComponent ? (
                    <InternalListComponent // todo: fix
                        {...listComponentProps}
                        {...internalListComponentProps}
                        isLoadingMore={isLoadingMore}
                    />
                ) : listType === 'checkbox' ? (
                    <OmniCheckboxList
                        {...listComponentProps}
                        {...internalListComponentProps}
                        isLoadingMore={isLoadingMore}
                    />
                ) : (
                    <OmniRadioList
                        {...listComponentProps}
                        isLoadingMore={isLoadingMore}
                    />
                )
            ) : isCreatable ? (
                <Box py={2}>
                    {!searchInput && filteredData.length === 0 && (
                        <Center>
                            <Text py={4}>{labelNoData}</Text>
                        </Center>
                    )}

                    {searchInput && filteredData.length === 0 && (
                        <VStack py={4}>
                            <Text>We couldn't find any matches</Text>
                            <Button
                                variant='ghost'
                                _hover={{
                                    _dark: {
                                        bg: 'tigeraGrey.800',
                                    },
                                }}
                                leftIcon={<AddIcon fontSize='2xs' />}
                                fontSize='sm'
                                onClick={() => {
                                    onClearSearch();
                                    listComponentProps.onChange([
                                        ...selectedFilters,
                                        {
                                            label: searchInput,
                                            value: searchInput,
                                        },
                                    ]);
                                    if (onRequestSearch) {
                                        onRequestSearch(filterId, '');
                                    }
                                }}
                                data-testid={`${testId}-create-filter-button`}
                            >
                                {formatCreatableLabel ? (
                                    formatCreatableLabel(searchInput)
                                ) : (
                                    <>Add "{searchInput}"</>
                                )}
                            </Button>
                        </VStack>
                    )}
                </Box>
            ) : (
                <Center>
                    <Text py={4}>{labelNoData}</Text>
                </Center>
            )}
        </>
    );
};

export default OmniInternalList;
