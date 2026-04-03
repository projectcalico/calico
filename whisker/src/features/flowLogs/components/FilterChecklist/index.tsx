import { useDebouncedCallback } from '@/hooks';
import { useOmniFilterQuery } from '@/hooks/omniFilters';
import {
    LazyOnReady,
    OmniFilterChangeEvent,
    OmniInternalList,
    PageCounter,
} from '@/libs/tigera/ui-components/components/common/OmniFilter';
import { OmniFilterOption } from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import SearchInput from '@/libs/tigera/ui-components/components/common/SearchInput';
import {
    DataListOmniFilterParam,
    FilterHintKey,
    FilterKey,
    transformToFlowsFilterQuery,
} from '@/utils/omniFilter';
import { Box, Button, Flex } from '@chakra-ui/react';
import React from 'react';
import FooterSkeleton from './FooterSkeleton';

type FilterChecklistProps = {
    testId: string;
    filterId: FilterHintKey;
    label: string;
    selectedValues: string[];
    filterQuery: Record<FilterHintKey, string[] | undefined>;
    onChange: (event: OmniFilterChangeEvent) => void;
    onClear: (filterId: FilterHintKey) => void;
};

const FilterChecklist: React.FC<FilterChecklistProps> = ({
    filterQuery,
    selectedValues,
    filterId,
    onChange,
    onClear,
    label,
    testId,
}) => {
    const { data, fetchData } = useOmniFilterQuery(filterId);
    const debounce = useDebouncedCallback();
    const { filters, isLoading, total } = data;
    const [isTyping, setIsTyping] = React.useState(false);
    const [isLoadingMore, setLoadingMore] = React.useState(false);
    const [searchInput, setSearchInput] = React.useState('');

    const selectedFilters =
        selectedValues?.map((value) => ({
            label: value,
            value,
        })) ?? [];

    React.useEffect(() => {
        if (!isLoading) {
            setLoadingMore(false);
        }
    }, [isLoading]);

    const getData = (searchOption?: string) => {
        const query = transformToFlowsFilterQuery(
            filterQuery as Record<FilterKey, string[]>,
            filterId as DataListOmniFilterParam,
            searchOption,
        );
        fetchData(query);
    };

    const handleRequestMore = () => {
        setLoadingMore(true);
        fetchData(null);
    };

    const onRequestSearch = (_filterId: string, searchOption: string) => {
        const requestData = () => {
            setIsTyping(false);
            return getData(searchOption);
        };
        setIsTyping(true);

        if (searchOption.length >= 1) {
            debounce(searchOption, requestData);
        } else {
            debounce(null, requestData);
        }
    };

    const handleChange = (filters: OmniFilterOption[]) => {
        onChange({
            filterId,
            filterLabel: label,
            operator: undefined,
            filters,
        });
    };

    const totalItems = total ?? 0;
    const filteredData = filters ?? [];
    const filteredSelectedOptions = selectedFilters.filter((filter) =>
        filter.label.includes(searchInput),
    );
    const hasFilters =
        filteredData.length > 0 || filteredSelectedOptions.length > 0;

    return (
        <Flex direction='column' gap={1}>
            <LazyOnReady onReady={getData} />

            <SearchInput
                variant='outline'
                placeholder='Search'
                value={searchInput}
                onChange={(value) => {
                    setSearchInput(value.trim());
                    onRequestSearch(filterId, value.trim());
                }}
                data-testid={`${testId}-search-filter`}
                iconButtonProps={
                    {
                        'data-testid': `${testId}-search-clear-button`,
                        'aria-label': 'Clear text',
                    } as any
                }
            />

            <Box minHeight='300px' maxHeight='500px' overflow='hidden'>
                <OmniInternalList
                    options={filteredData}
                    selectedOptions={selectedFilters}
                    filteredSelectedOptions={filteredSelectedOptions}
                    showSelectedList
                    emptyMessage='labelNoSearchResults'
                    showMoreButton={
                        totalItems > 0 && filteredData.length < totalItems
                    }
                    isLoadingMore={isLoadingMore}
                    labelShowMore='Show more'
                    labelListHeader='Filters'
                    labelSelectedListHeader=''
                    onChange={handleChange}
                    onRequestMore={handleRequestMore}
                    ref={undefined}
                    listType='checkbox'
                    isCreatable
                    searchInput={searchInput}
                    filteredData={filteredData}
                    selectedFilters={selectedFilters}
                    labelNoData='No filters available'
                    testId={testId}
                    onClearSearch={() => setSearchInput('')}
                    isLoading={isLoading || isTyping}
                    hasFilters={hasFilters}
                    filterId={filterId}
                    onRequestSearch={onRequestSearch}
                />
            </Box>

            {totalItems > 0 && !isTyping && (
                <Flex justifyContent='space-between'>
                    <Button
                        isDisabled={selectedFilters.length === 0}
                        variant='ghost'
                        fontWeight='semibold'
                        size='sm'
                        tabIndex={0}
                        onClick={() => {
                            onClear(filterId);

                            // only way to guarantee focus post clear as dependant on rendering cycle
                            // of list inside omnifilter
                            // setTimeout(() => {
                            //     initialFocusRef.current?.focus();
                            //     setTimeout(
                            //         () => initialFocusRef.current?.focus(),
                            //         500,
                            //     );
                            // }, 500);
                        }}
                    >
                        Clear
                    </Button>
                    <PageCounter>{`${filteredData.length} of ${totalItems}`}</PageCounter>
                </Flex>
            )}

            {(isLoading || isTyping) && <FooterSkeleton />}
        </Flex>
    );
};

export default FilterChecklist;
