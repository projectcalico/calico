import { useDebouncedCallback } from '@/hooks';
import {
    OmniFilter,
    OmniFilterList,
} from '@/libs/tigera/ui-components/components/common';
import { OmniFilterChangeEvent } from '@/libs/tigera/ui-components/components/common/OmniFilter';
import PortOmniFilter from '@/features/flowLogs/components/PortOmniFilter';
import { OmniFilterDataQuery } from '@/types/api';
import {
    ListOmniFilterParam,
    OmniFilterProperties,
    ListOmniFiltersData,
    SelectedOmniFilterOptions,
    SelectedOmniFilters,
    OmniFilterKeys,
    CustomOmniFilterKeys,
    ListOmniFilterKeys,
} from '@/utils/omniFilter';
import React from 'react';

const listOmniFilterIds = Object.values(ListOmniFilterKeys);

const omniFilterIds = [
    ...listOmniFilterIds,
    ...Object.values(CustomOmniFilterKeys),
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
    const [isLoading, setIsLoading] = React.useState(false);

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
                    filters={omniFilterData[filterId].filters ?? []}
                    selectedFilters={selectedListOmniFilters[filterId]}
                    onChange={onChange}
                    onClear={() => handleClear(filterId)}
                    showOperatorSelect={false}
                    listType='checkbox'
                    isLoading={omniFilterData[filterId].isLoading || isLoading}
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
                            setIsLoading(false);
                        };

                        if (searchOption.length >= 1) {
                            setIsLoading(true);
                            debounce(searchOption, requestData);
                        } else {
                            requestData();
                        }
                    }}
                    onRequestMore={(filterId) =>
                        onRequestNextPage(filterId as ListOmniFilterParam)
                    }
                    showSelectedList
                    isCreatable
                    labelSelectedListHeader=''
                    labelListHeader='Filters'
                />
            ))}

            <PortOmniFilter
                key='port-omni-filter'
                port={selectedValues.dest_port?.[0] ?? ''}
                protocol={selectedValues.protocol?.[0] ?? ''}
                selectedFilters={[
                    ...(selectedValues.dest_port ?? []),
                    ...(selectedValues.protocol ?? []),
                ]}
                onChange={({ protocol, port }) =>
                    onMultiChange(
                        [OmniFilterKeys.protocol, OmniFilterKeys.dest_port],
                        [protocol, port],
                    )
                }
                filterId={CustomOmniFilterKeys.dest_port}
                filterLabel={
                    OmniFilterProperties[OmniFilterKeys.dest_port].label
                }
            />
        </OmniFilterList>
    );
};

export default OmniFilters;
