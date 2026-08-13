import { useFlowLogsUrlFilters } from '@/hooks/useFlowLogsUrlFilters';
import { OmniFilter } from '@/libs/tigera/ui-components/components/common';
import { OmniFilterChangeEvent } from '@/libs/tigera/ui-components/components/common/OmniFilter';
import { OmniFilterOption } from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import { ReporterLabels } from '@/types/render';
import { FilterKeys } from '@/utils/filters/urlKeys';
import React from 'react';

const options: OmniFilterOption[] = [
    { label: ReporterLabels.Src, value: 'Src' },
    { label: ReporterLabels.Dst, value: 'Dst' },
];

const formatSelectedLabel = (selectedFilters: OmniFilterOption[]) => {
    const [selectedFilter] = selectedFilters;

    return selectedFilter
        ? ReporterLabels[selectedFilter.value as keyof typeof ReporterLabels]
        : '';
};

type ReporterOmniFilterProps = {
    filterId: typeof FilterKeys.reporter;
    filterLabel: string;
    selectedFilters: OmniFilterOption[];
};

const ReporterOmniFilter: React.FC<ReporterOmniFilterProps> = ({
    filterId,
    filterLabel,
    selectedFilters,
}) => {
    const { setFilter } = useFlowLogsUrlFilters();

    const handleChange = (event: OmniFilterChangeEvent) =>
        setFilter(
            filterId,
            event.filters.map((filter) => filter.value),
        );

    return (
        <OmniFilter
            filterId={filterId}
            filterLabel={filterLabel}
            filters={options}
            selectedFilters={selectedFilters}
            onChange={handleChange}
            onClear={() => setFilter(filterId, [])}
            showOperatorSelect={false}
            listType='radio'
            showSearch={false}
            onReady={() => undefined}
            width='100px'
            popoverContentProps={{ width: '175px' }}
            formatSelectedLabel={formatSelectedLabel}
            showSelectedList
            labelSelectedListHeader=''
            labelListHeader='Filters'
        />
    );
};

export default ReporterOmniFilter;
