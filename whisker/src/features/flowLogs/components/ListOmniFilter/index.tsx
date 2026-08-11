import { useOmniFilterOptions } from '@/hooks/omniFilters';
import { useFlowLogsUrlFilters } from '@/hooks/useFlowLogsUrlFilters';
import { OmniFilter } from '@/libs/tigera/ui-components/components/common';
import { OmniFilterChangeEvent } from '@/libs/tigera/ui-components/components/common/OmniFilter';
import { OmniFilterOption } from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import {
    ListFilterId,
    OmniFilterProperties,
    StaticFilterId,
} from '@/utils/omniFilter';
import React from 'react';

type ListOmniFilterProps = {
    filterId: ListFilterId | StaticFilterId;
    filterLabel: string;
    // The selection is owned by the URL and passed in by the filter bar
    // rather than read here: OmniFilterList inspects its children's
    // selectedFilters props to decide whether to show the Reset button.
    selectedFilters: OmniFilterOption[];
};

/**
 * A generic paged autocomplete filter chip that fetches its own options
 * from flows-filter-hints and writes its selection to the URL. 'static'
 * filters (reporter) render through it too, overriding the fetching
 * behaviour via their registry filterComponentProps.
 */
const ListOmniFilter: React.FC<ListOmniFilterProps> = ({
    filterId,
    filterLabel,
    selectedFilters,
}) => {
    const { setFilter } = useFlowLogsUrlFilters();
    const {
        options,
        isLoading,
        total,
        requestOptions,
        requestSearch,
        requestNextPage,
    } = useOmniFilterOptions(filterId);

    const handleChange = (event: OmniFilterChangeEvent) =>
        setFilter(
            filterId,
            event.filters.map((filter) => filter.value),
        );

    return (
        <OmniFilter
            filterId={filterId}
            filterLabel={filterLabel}
            filters={options ?? []}
            selectedFilters={selectedFilters}
            onChange={handleChange}
            onClear={() => setFilter(filterId, [])}
            showOperatorSelect={false}
            listType='checkbox'
            isLoading={isLoading}
            totalItems={total}
            onReady={() => requestOptions('')}
            onRequestSearch={(_filterId, searchOption) =>
                requestSearch(searchOption)
            }
            onRequestMore={requestNextPage}
            showSelectedList
            isCreatable
            labelSelectedListHeader=''
            labelListHeader='Filters'
            {...OmniFilterProperties[filterId].filterComponentProps}
        />
    );
};

export default ListOmniFilter;
