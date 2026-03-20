import { useDebouncedCallback } from '@/hooks';
import { useOmniFilterQuery } from '@/hooks/omniFilters';
import OmniFilter, {
    OmniFilterChangeEvent,
} from '@/libs/tigera/ui-components/components/common/OmniFilter';
import { OmniFilterOption } from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import { SelectOption } from '@/libs/tigera/ui-components/components/common/Select';
import {
    DataListOmniFilterParam,
    FilterHintKey,
    FilterKey,
    transformToFlowsFilterQuery,
} from '@/utils/omniFilter';
import React from 'react';

type PolicySelectProps = {
    filterKey: FilterHintKey;
    value: OmniFilterOption | null | undefined;
    onChange: (value: SelectOption | null) => void;
    showSearch?: boolean;
};

const PolicySelect: React.FC<PolicySelectProps> = ({
    filterKey,
    value,
    onChange,
    showSearch = true,
}) => {
    const { data, fetchData } = useOmniFilterQuery(filterKey);
    const debounce = useDebouncedCallback();
    const { filters, isLoading, total } = data;
    const [isTyping, setIsTyping] = React.useState(false);

    const getData = (searchOption?: string) => {
        const query = transformToFlowsFilterQuery(
            {} as Record<FilterKey, string[]>,
            filterKey as DataListOmniFilterParam,
            searchOption,
        );
        fetchData(query);
    };

    const handleRequestMore = () => {
        fetchData(null);
    };

    const handleChange = (change: OmniFilterChangeEvent) => {
        onChange(change.filters[0]);
    };

    const onRequestSearch = React.useCallback(
        (_filterId: string, searchOption: string) => {
            const requestData = () => {
                setIsTyping(false);
                getData(searchOption);
            };

            if (searchOption.length >= 1) {
                setIsTyping(true);
                debounce(searchOption, requestData);
            } else {
                requestData();
            }
        },
        [],
    );

    const partsProps = React.useMemo(
        () => ({
            triggerProps: {
                isActive: false,
                buttonProps: {
                    width: 'full',
                    justifyContent: 'space-between',
                    py: '5',
                    bg: 'experimental-token-bg-input',
                    _hover: {
                        bg: 'experimental-token-bg-input',
                    },
                    _expanded: {
                        bg: 'experimental-token-bg-input',
                    },
                },
                customContent: value ? (
                    <p>{value.label}</p>
                ) : (
                    <p className='text-tigera-token-fg-subtle'>Select...</p>
                ),
            },
        }),
        [value?.label],
    );

    return (
        <OmniFilter
            key={filterKey}
            filterId={filterKey}
            filterLabel=''
            filters={filters ?? []}
            selectedFilters={value ? [value] : []}
            onChange={handleChange}
            onClear={() => onChange(null)}
            showOperatorSelect={false}
            listType='select'
            isLoading={isLoading || isTyping}
            totalItems={total ?? 0}
            onReady={() => getData('')}
            onRequestSearch={onRequestSearch}
            onRequestMore={handleRequestMore}
            showSelectedList
            isCreatable
            showSearch={showSearch}
            partsProps={partsProps}
            popoverContentProps={{
                width: '400px',
            }}
        />
    );
};

export default PolicySelect;
