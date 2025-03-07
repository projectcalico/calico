import {
    OmniFilter,
    OmniFilterList,
} from '@/libs/tigera/ui-components/components/common';
import { OmniFilterChangeEvent } from '@/libs/tigera/ui-components/components/common/OmniFilter';
import { OmniFilterDataQuery } from '@/types/api';
import {
    OmniFilterParam,
    OmniFilterProperties,
    OmniFiltersData,
    SelectedOmniFilterOptions,
} from '@/utils/omniFilter';
import React from 'react';

const omniFilterIds: OmniFilterParam[] = Object.values(OmniFilterParam);

type OmniFiltersProps = {
    onChange: (event: OmniFilterChangeEvent) => void;
    onReset: () => void;
    omniFilterData: OmniFiltersData;
    selectedOmniFilters: SelectedOmniFilterOptions;
    onRequestFilterData: (query: OmniFilterDataQuery) => void;
    onRequestNextPage: (filterId: OmniFilterParam) => void;
};

const OmniFilters: React.FC<OmniFiltersProps> = ({
    onChange,
    onReset,
    omniFilterData,
    selectedOmniFilters,
    onRequestFilterData,
    onRequestNextPage,
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
                    filters={omniFilterData?.[filterId].filters ?? []}
                    selectedFilters={selectedOmniFilters[filterId]}
                    onChange={onChange}
                    onClear={() => handleClear(filterId)}
                    showOperatorSelect={false}
                    listType='checkbox'
                    isLoading={omniFilterData[filterId].isLoading}
                    totalItems={omniFilterData[filterId].total}
                    onReady={() => {
                        if (omniFilterData[filterId].filters === null) {
                            onRequestFilterData({
                                filterParam: filterId,
                                page: 1,
                                searchOption: '',
                            });
                        }
                    }}
                    onRequestSearch={(filterId, searchOption) => {
                        onRequestFilterData({
                            filterParam: filterId as OmniFilterParam,
                            page: 1,
                            searchOption,
                        });
                    }}
                    onRequestMore={(filterId) =>
                        onRequestNextPage(filterId as OmniFilterParam)
                    }
                    // isDisabled
                />
            ))}
        </OmniFilterList>
    );
};

export default OmniFilters;
