import {
    OmniFilter,
    OmniFilterList,
} from '@/libs/tigera/ui-components/components/common';
import { OmniFilterChangeEvent } from '@/libs/tigera/ui-components/components/common/OmniFilter';
import {
    OmniFilterParam,
    OmniFilterProperties,
    SelectedOmniFilterOptions,
} from '@/utils/omniFilter';
import React from 'react';

const omniFilterIds: OmniFilterParam[] = Object.values(OmniFilterParam);

type OmniFiltersProps = {
    onChange: (event: OmniFilterChangeEvent) => void;
    onReset: () => void;
    selectedFilters: SelectedOmniFilterOptions;
};

const OmniFilters: React.FC<OmniFiltersProps> = ({
    onChange,
    onReset,
    selectedFilters,
}) => {
    const handleClear = (filterId: string) =>
        onChange({
            filterId: filterId,
            filterLabel: '',
            filters: [],
            operator: undefined,
        });

    return (
        <OmniFilterList
            gap={2}
            defaultFilterIds={omniFilterIds}
            visibleFilterIds={omniFilterIds}
            onChangeVisible={() => undefined}
            onResetVisible={onReset}
        >
            {omniFilterIds.map((filterId) => (
                <OmniFilter
                    filterId={filterId}
                    filterLabel={OmniFilterProperties[filterId].label}
                    filters={OmniFilterProperties[filterId].selectOptions!}
                    selectedFilters={selectedFilters[filterId]}
                    onChange={onChange}
                    onClear={() => handleClear(filterId)}
                    showOperatorSelect={false}
                    listType='checkbox'
                />
            ))}
        </OmniFilterList>
    );
};

export default OmniFilters;
