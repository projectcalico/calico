import { BoxProps, Button, Flex, Text } from '@chakra-ui/react';
import React, { useEffect } from 'react';
import OmniCheckboxList, {
    OmniCheckboxListProps,
} from './components/OmniCheckboxList';
import { useOmniFilterUrlState } from './hooks';
import SearchInput from '../SearchInput';
import OmniFilterOperatorSelect from './components/OmniFilterOperatorSelect';
import { CheckboxListLoadingSkeleton } from './components/CheckboxLoadingSkeleton';
import {
    OmniFilterOption,
    OmniInternalListComponentProps,
    OperatorType,
} from './types';
import OmniRadioList from './components/OmniRadioList';
import OmniRangeList from './components/OmniRangeList';
import OmniSwitchList from './components/OmniSwitchList';
import { totalItemsLabelStyles } from './styles';
import {
    OmniFilterBody,
    OmniFilterContainer,
    OmniFilterContent,
    OmniFilterFooter,
    OmniFilterHeader,
    OmniFilterTrigger,
} from './parts';

// Handle calling onReady for lazy loaded content
const LazyOnReady: React.FC<{ onReady?: () => void }> = ({ onReady }) => {
    useEffect(() => onReady && onReady(), []);

    return null;
};

export type OmniFilterChangeEvent = {
    filterId: string;
    filterLabel: string;
    operator: string | undefined;
    filters: OmniFilterOption[];
};

export type ListType = 'checkbox' | 'radio';

const BUTTON_LABEL_WIDTH = '190px';
const BUTTON_LABEL_WITH_COUNT_WIDTH = '160px';

export type OmniFilterProps = {
    filterId: string;
    filterLabel: string;
    labelClearSelection?: string;
    labelShowMore?: string;
    labelNoData?: string;
    labelNoSearchResults?: string;
    labelSearchPlaceholder?: string;
    labelListHeader?: string;
    labelSelectedListHeader?: string;
    filters: OmniFilterOption[];
    totalItems?: number;
    listType?: ListType;
    internalListComponent?: React.ComponentType<OmniInternalListComponentProps>;
    internalListComponentProps?: any;
    isLoading?: boolean;
    isDisabled?: boolean;
    selectedFilters: OmniFilterOption[];
    selectedOperator?: string;
    showButtonIcon?: boolean;
    showSelectedList?: boolean;
    showOperatorSelect?: boolean;
    showSearch?: boolean;
    showSelectedOnButton?: boolean;
    inMemorySearch?: boolean;
    onRequestMore?: (filterId: string, searchOption: string) => void;
    onRequestSearch?: (filterId: string, searchOption: string) => void;
    onChange: (change: OmniFilterChangeEvent) => void;
    onClear: () => void;
    onReady?: () => void;
    formatOperatorLabel?: (option: OmniFilterOption) => string;
    formatSelectedLabel?: (selectedFilters: OmniFilterOption[]) => string;
    formatListCountLabel?: (listCount: number, totalItems: number) => string;
} & Omit<BoxProps, 'onChange'> & { 'data-testid'?: string };

type CheckboxOmniFilterProps = {
    listType: 'checkbox';
    internalListComponentProps?: OmniCheckboxListProps;
} & Omit<OmniFilterProps, 'listType' | 'internalListComponentProps'>;

const OmniFilter: React.FC<OmniFilterProps | CheckboxOmniFilterProps> = ({
    filterId,
    filterLabel,
    labelClearSelection = 'Clear selection',
    labelNoData = 'No filters available',
    labelNoSearchResults = 'No matches found',
    labelSearchPlaceholder = 'Search',
    labelShowMore = 'Show more',
    labelListHeader = 'Items',
    labelSelectedListHeader = 'Selected Items',
    filters = [],
    selectedFilters = [],
    selectedOperator = OperatorType.Equals,
    listType = 'checkbox',
    internalListComponent,
    internalListComponentProps,
    isLoading = false,
    isDisabled = false,
    showButtonIcon = true,
    showOperatorSelect = true,
    showSearch = true,
    showSelectedOnButton = true,
    showSelectedList = false,
    inMemorySearch = false,
    totalItems,
    onChange,
    onReady,
    onClear,
    onRequestMore,
    onRequestSearch,
    formatSelectedLabel,
    formatOperatorLabel,
    formatListCountLabel = (listCount, totalItems) =>
        `${listCount} of ${totalItems}`,
    ...rest
}) => {
    const [isOpen, setIsOpen] = React.useState(false);
    const [isLoadingMore, setLoadingMore] = React.useState(false);

    const [filteredData, setFilterData] = React.useState(filters);
    const [searchInput, setSearchInput] = React.useState('');

    const hasFilters = filters.length > 0;
    const [firstSelectedFilter, ...remainingSelectedFilters] = selectedFilters;
    const InternalListComponent = internalListComponent;
    const popoverContentRef = React.useRef<HTMLElement>(null);
    const initialFocusRef = React.useRef<HTMLInputElement>(null);
    const testId = rest['data-testid'] ?? 'omni-filter';

    React.useEffect(() => {
        // only refresh changed filters when inMemorySearch if no search is taking place
        if (!inMemorySearch || (inMemorySearch && searchInput.length === 0)) {
            setFilterData(filters);
        }
    }, [filters]);

    React.useEffect(() => {
        if (!isLoading && isLoadingMore) {
            setLoadingMore(false);
            initialFocusRef.current?.focus();
        }
    }, [isLoading]);

    const listComponentProps = {
        options: filteredData,
        selectedOptions: selectedFilters,
        emptyMessage: labelNoSearchResults,
        showMoreButton: totalItems && filteredData.length < totalItems,
        showSelectedList,
        isLoadingMore,
        labelShowMore,
        height: 300,
        labelListHeader,
        labelSelectedListHeader,
        ref: showSearch ? undefined : initialFocusRef, // focus on first in list when no search
        onChange: (filters: OmniFilterOption[]) => {
            onChange({
                filterId,
                filterLabel,
                operator: showOperatorSelect ? selectedOperator : undefined,
                filters,
            });
            popoverContentRef?.current?.focus();
        },
        onRequestMore: () => {
            if (onRequestMore) {
                setLoadingMore(true);
                onRequestMore(filterId, searchInput);
            }
        },
    } as OmniInternalListComponentProps;

    return (
        <>
            <OmniFilterContainer
                onClose={() => setIsOpen(false)}
                initialFocusRef={initialFocusRef}
            >
                <OmniFilterTrigger
                    isOpen={isOpen}
                    onClick={() => setIsOpen(true)}
                    label={filterLabel}
                    isActive={firstSelectedFilter && showSelectedOnButton}
                    isDisabled={isDisabled}
                    testId={testId}
                    showButtonIcon={showButtonIcon}
                    selectedValueLabel={
                        formatSelectedLabel
                            ? formatSelectedLabel(selectedFilters)
                            : firstSelectedFilter?.label
                    }
                    operator={selectedOperator}
                    selectedValueTitle={
                        !formatSelectedLabel
                            ? selectedFilters
                                  .map((filter) => filter.label)
                                  .join(', ')
                            : undefined
                    }
                    showSelectedValueLabel={showSelectedOnButton}
                    badgeLabel={
                        remainingSelectedFilters.length > 0 &&
                        !formatSelectedLabel
                            ? remainingSelectedFilters.length
                            : undefined
                    }
                    valueSx={
                        formatSelectedLabel
                            ? { maxWidth: BUTTON_LABEL_WIDTH }
                            : {
                                  maxWidth:
                                      remainingSelectedFilters.length > 0
                                          ? BUTTON_LABEL_WITH_COUNT_WIDTH
                                          : BUTTON_LABEL_WIDTH,
                              }
                    }
                />

                <OmniFilterContent
                    data-testid={`${testId}-popover-content`}
                    ref={popoverContentRef}
                >
                    <LazyOnReady onReady={onReady} />

                    {(showOperatorSelect || showSearch) && (
                        <OmniFilterHeader
                            data-testid={`${testId}-popover-header`}
                        >
                            <Flex gap={2} flexDirection='column'>
                                {showOperatorSelect && (
                                    <OmniFilterOperatorSelect
                                        value={selectedOperator}
                                        label={filterLabel}
                                        onChange={(operator) => {
                                            onChange({
                                                filterId,
                                                filterLabel,
                                                operator: showOperatorSelect
                                                    ? operator
                                                    : undefined,
                                                filters: selectedFilters,
                                            });
                                        }}
                                        data-testid={`${testId}-operator-select`}
                                        getOptionLabel={formatOperatorLabel}
                                    />
                                )}
                                {showSearch && (
                                    <SearchInput
                                        placeholder={labelSearchPlaceholder}
                                        value={searchInput}
                                        onChange={(value) => {
                                            setSearchInput(value.trim());
                                            if (inMemorySearch) {
                                                setFilterData(
                                                    filters.filter(
                                                        ({ label }) =>
                                                            label
                                                                .toLocaleUpperCase()
                                                                .includes(
                                                                    value.toLocaleUpperCase(),
                                                                ),
                                                    ),
                                                );
                                            } else {
                                                if (onRequestSearch) {
                                                    onRequestSearch(
                                                        filterId,
                                                        value.trim(),
                                                    );
                                                }
                                            }
                                        }}
                                        data-testid={`${testId}-search-filter`}
                                        iconButtonProps={
                                            {
                                                'data-testid': `${testId}-search-clear-button`,
                                                'aria-label': 'Clear text',
                                            } as any
                                        }
                                        ref={initialFocusRef}
                                    />
                                )}
                            </Flex>
                        </OmniFilterHeader>
                    )}

                    <OmniFilterBody
                        px={hasFilters ? 0 : 3}
                        pt={!showOperatorSelect && !showSearch ? 2 : 0}
                    >
                        {isLoading && !isLoadingMore ? (
                            <CheckboxListLoadingSkeleton
                                numberOfLines={8}
                                data-testid={`${testId}-list-skeleton`}
                            />
                        ) : hasFilters ? (
                            InternalListComponent ? (
                                <InternalListComponent
                                    {...listComponentProps}
                                    {...internalListComponentProps}
                                />
                            ) : listType === 'checkbox' ? (
                                <OmniCheckboxList
                                    {...listComponentProps}
                                    {...internalListComponentProps}
                                />
                            ) : (
                                <OmniRadioList {...listComponentProps} />
                            )
                        ) : (
                            <Text py={2}>{labelNoData}</Text>
                        )}
                    </OmniFilterBody>

                    <OmniFilterFooter
                        alignItems='center'
                        justifyContent='space-between'
                    >
                        <Button
                            isDisabled={selectedFilters.length === 0}
                            variant='ghost'
                            fontWeight='semibold'
                            size='sm'
                            onClick={() => {
                                onClear();

                                // only way to guarantee focus post clear as dependant on rendering cycle
                                // of list inside omnifilter
                                setTimeout(() => {
                                    initialFocusRef.current?.focus();
                                    setTimeout(
                                        () => initialFocusRef.current?.focus(),
                                        500,
                                    );
                                }, 500);
                            }}
                        >
                            {labelClearSelection}
                        </Button>

                        {totalItems ? (
                            <Text sx={totalItemsLabelStyles}>
                                {formatListCountLabel(
                                    filteredData.length,
                                    totalItems,
                                )}
                            </Text>
                        ) : (
                            ''
                        )}
                    </OmniFilterFooter>
                </OmniFilterContent>
            </OmniFilterContainer>
        </>
    );
};

export default OmniFilter;

export {
    OmniCheckboxList,
    OmniRadioList,
    OmniRangeList,
    OmniSwitchList,
    useOmniFilterUrlState,
};
