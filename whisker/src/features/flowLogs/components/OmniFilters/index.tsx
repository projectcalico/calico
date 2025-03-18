import { useDebouncedCallback } from '@/hooks';
import {
    OmniFilter,
    OmniFilterList,
} from '@/libs/tigera/ui-components/components/common';
import { OmniFilterChangeEvent } from '@/libs/tigera/ui-components/components/common/OmniFilter';
import PortOmniFilter from '@/features/flowLogs/components/PortOmniFilter';
import { OmniFilterDataQuery } from '@/types/api';
import {
    CustomOmniFilterParam,
    ListOmniFilterParam,
    OmniFilterParam,
    OmniFilterProperties,
    ListOmniFiltersData,
    SelectedOmniFilterOptions,
    SelectedOmniFilters,
} from '@/utils/omniFilter';
import React from 'react';

const listOmniFilterIds = Object.values(ListOmniFilterParam);

const omniFilterIds = [
    ...listOmniFilterIds,
    ...Object.values(CustomOmniFilterParam),
];

type OmniFiltersProps = {
    onChange: (event: OmniFilterChangeEvent) => void;
    onMultiChange: (filterIds: string[], values: (string | null)[]) => void;
    onReset: () => void;
    omniFilterData: ListOmniFiltersData;
    selectedValues: SelectedOmniFilters;
    selectedListOmniFilters: SelectedOmniFilterOptions;
    onRequestFilterData: (query: OmniFilterDataQuery) => void;
    onRequestNextPage: (filterId: ListOmniFilterParam) => void;
};

const OmniFilters: React.FC<OmniFiltersProps> = ({
    onChange,
    onMultiChange,
    onReset,
    omniFilterData,
    selectedListOmniFilters,
    selectedValues,
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

    const debounce = useDebouncedCallback();

    return (
        <OmniFilterList
            gap={2}
            defaultFilterIds={omniFilterIds}
            visibleFilterIds={omniFilterIds}
            onChangeVisible={() => undefined}
            onResetVisible={onReset}
        >
            {listOmniFilterIds.map((filterId) => (
                <OmniFilter
                    filterId={filterId}
                    filterLabel={OmniFilterProperties[filterId].label}
                    filters={omniFilterData?.[filterId].filters ?? []}
                    selectedFilters={selectedListOmniFilters[filterId]}
                    onChange={onChange}
                    onClear={() => handleClear(filterId)}
                    showOperatorSelect={false}
                    listType='checkbox'
                    isLoading={omniFilterData[filterId].isLoading}
                    totalItems={omniFilterData[filterId].total}
                    onReady={() =>
                        onRequestFilterData({
                            filterParam: filterId,
                            searchOption: '',
                        })
                    }
                    onRequestSearch={(filterId, searchOption) => {
                        const requestData = () => {
                            onRequestFilterData({
                                filterParam: filterId as ListOmniFilterParam,
                                searchOption,
                            });
                        };

                        if (searchOption.length >= 1) {
                            debounce(searchOption, requestData);
                        } else {
                            requestData();
                        }
                    }}
                    onRequestMore={(filterId) =>
                        onRequestNextPage(filterId as ListOmniFilterParam)
                    }
                />
            ))}

            <PortOmniFilter
                port={selectedValues?.port?.[0] ?? ''}
                protocol={selectedValues?.protocol?.[0] ?? ''}
                selectedFilters={[
                    ...(selectedValues?.port ?? []),
                    ...(selectedValues?.protocol ?? []),
                ]}
                onChange={({ protocol, port }) =>
                    onMultiChange(
                        [OmniFilterParam.protocol, OmniFilterParam.port],
                        [protocol, port],
                    )
                }
                filterId={CustomOmniFilterParam.port}
                filterLabel={OmniFilterProperties[OmniFilterParam.port].label}
            />
        </OmniFilterList>
    );
};

export default OmniFilters;
