import { useOmniFilterOptions } from '@/hooks/omniFilters';
import { useFlowLogsUrlFilters } from '@/hooks/useFlowLogsUrlFilters';
import { OmniFilter } from '@/libs/tigera/ui-components/components/common';
import { OmniFilterChangeEvent } from '@/libs/tigera/ui-components/components/common/OmniFilter';
import { OmniFilterOption } from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import React from 'react';
import { tableLevelDataFilterIds } from '../TableFilters/filters';

type TableLevelDataFilterId = (typeof tableLevelDataFilterIds)[number];

type ListOmniFilterProps = {
    filterId: TableLevelDataFilterId;
    filterLabel: string;
    selectedFilters: OmniFilterOption[];
};

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
        />
    );
};

export default ListOmniFilter;
