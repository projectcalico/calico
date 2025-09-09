import { useDebouncedCallback } from '@/hooks';
import { useOmniFilterQuery } from '@/hooks/omniFilters';
import { OmniFilter } from '@/libs/tigera/ui-components/components/common';
import { OmniFilterChangeEvent } from '@/libs/tigera/ui-components/components/common/OmniFilter';
import {
    FilterHintKey,
    FilterKey,
    ListOmniFilterParam,
    transformToFlowsFilterQuery,
} from '@/utils/omniFilter';
import React from 'react';

type PolicyListOmniFilterProps = {
    filterId: FilterHintKey;
    label: string;
    selectedValues: string[];
    filterQuery: Record<FilterHintKey, string[] | undefined>;
    onChange: (event: OmniFilterChangeEvent) => void;
    onClear: (filterId: FilterHintKey) => void;
};

const PolicyListOmniFilter: React.FC<PolicyListOmniFilterProps> = ({
    filterQuery,
    selectedValues,
    filterId,
    onChange,
    onClear,
    label,
}) => {
    const { data, fetchData } = useOmniFilterQuery(filterId);
    const debounce = useDebouncedCallback();
    const { filters, isLoading, total } = data;

    const selectedFilters =
        selectedValues?.map((value) => ({
            label: value,
            value,
        })) ?? [];

    const getData = (searchOption?: string) => {
        const query = transformToFlowsFilterQuery(
            filterQuery as Record<FilterKey, string[]>,
            filterId as ListOmniFilterParam,
            searchOption,
        );
        fetchData(query);
    };

    const handleRequestMore = () => fetchData(null);

    return (
        <OmniFilter
            filterId={filterId}
            filterLabel={label}
            onChange={onChange}
            listType='checkbox'
            filters={filters ?? []}
            selectedFilters={selectedFilters}
            onClear={() => onClear(filterId)}
            showOperatorSelect={false}
            isLoading={isLoading}
            totalItems={total ?? 0}
            onReady={getData}
            onRequestSearch={(_filterId, searchOption) => {
                const requestData = () => getData(searchOption);

                if (searchOption.length >= 1) {
                    debounce(searchOption, requestData);
                } else {
                    requestData();
                }
            }}
            onRequestMore={handleRequestMore}
            isCreatable
            labelSelectedListHeader=''
            labelListHeader='Filters'
            triggerType='taglist'
            tagListTriggerProps={{
                container: {
                    id: `${filterId}-taglist`,
                },
            }}
            popoverContentProps={{
                width: '475px',
                sx: {
                    _dark: {
                        border: '1px solid',
                        borderColor: 'tigeraGrey.600',
                        backgroundColor: 'tigeraGrey.1000',
                        boxShadow: 'none!important',
                    },
                },
            }}
        />
    );
};

export default PolicyListOmniFilter;
