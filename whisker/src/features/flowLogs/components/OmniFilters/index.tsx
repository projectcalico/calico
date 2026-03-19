import PortOmniFilter from '@/features/flowLogs/components/PortOmniFilter';
import { useDebouncedCallback } from '@/hooks';
import {
    OmniFilter,
    OmniFilterList,
} from '@/libs/tigera/ui-components/components/common';
import { OmniFilterChangeEvent } from '@/libs/tigera/ui-components/components/common/OmniFilter';
import { OmniFilterDataQuery } from '@/types/api';
import {
    CustomOmniFilterKeys,
    DataListOmniFilterParam,
    FilterKey,
    ListOmniFilterKeys,
    ListOmniFiltersData,
    OmniFilterKeys,
    OmniFilterProperties,
    SelectedOmniFilterOptions,
    SelectedOmniFilters,
} from '@/utils/omniFilter';
import React from 'react';
import ActionOmniFilter from '../ActionOmniFilter';
import PolicyOmniFilter, { PolicyFilter } from '../PolicyOmniFilter';
import StartTimeOmniFilter from '../StartTimeOmniFilter';

const listOmniFilterIds = Object.values(ListOmniFilterKeys);

const omniFilterIds = [
    ...listOmniFilterIds,
    ...Object.values(CustomOmniFilterKeys),
];

type OmniFiltersProps = {
    onChange: (filterId: string, filters: string[] | null) => void;
    onMultiChange: (change: Partial<Record<FilterKey, string[]>>) => void;
    onReset: () => void;
    omniFilterData: ListOmniFiltersData;
    selectedValues: SelectedOmniFilters;
    selectedListOmniFilters: SelectedOmniFilterOptions;
    onRequestFilterData: (query: OmniFilterDataQuery) => void;
    onRequestNextPage: (filterId: DataListOmniFilterParam) => void;
    startTime: number;
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
    startTime,
}) => {
    const handleClear = (filterId: string) => onChange(filterId, []);

    const debounce = useDebouncedCallback();
    const [isLoading, setIsLoading] = React.useState(false);

    const policyFilters = React.useMemo(
        () =>
            [
                selectedValues.policy,
                selectedValues.policyNamespace,
                selectedValues.policyTier,
                selectedValues.policyKind,
            ]
                .filter(Boolean)
                .flat() as string[],
        [
            selectedValues.policy?.length,
            selectedValues.policyNamespace?.length,
            selectedValues.policyTier?.length,
            selectedValues.policyKind?.length,
        ],
    );

    const handleChange = (omniFilterChangeEvent: OmniFilterChangeEvent) => {
        onChange(
            omniFilterChangeEvent.filterId,
            omniFilterChangeEvent.filters.map((filter) => filter.value),
        );
    };

    const handlePolicyFilterChange = (filterId: string, value: string) => {
        onChange(filterId, value ? [value] : null);
    };

    return (
        <>
            <OmniFilterList
                gap={2}
                defaultFilterIds={omniFilterIds}
                visibleFilterIds={omniFilterIds}
                onChangeVisible={() => undefined}
                onResetVisible={onReset}
            >
                <PolicyOmniFilter
                    key='policy-omni-filter'
                    onChange={handlePolicyFilterChange}
                    filterId={CustomOmniFilterKeys.policy}
                    selectedFilters={policyFilters as PolicyFilter[]}
                    onClear={() => handleClear(FilterKey.policy)}
                />

                {listOmniFilterIds.map((id) => {
                    const filterId = id as DataListOmniFilterParam;
                    return (
                        <OmniFilter
                            key={filterId}
                            filterId={filterId}
                            filterLabel={OmniFilterProperties[filterId].label}
                            filters={omniFilterData[filterId]?.filters ?? []}
                            selectedFilters={selectedListOmniFilters[filterId]}
                            onChange={handleChange}
                            onClear={() => handleClear(filterId)}
                            showOperatorSelect={false}
                            listType='checkbox'
                            isLoading={
                                omniFilterData[filterId]?.isLoading || isLoading
                            }
                            totalItems={omniFilterData[filterId]?.total}
                            onReady={() =>
                                onRequestFilterData({
                                    filterParam: filterId,
                                    searchOption: '',
                                })
                            }
                            onRequestSearch={(filterId, searchOption) => {
                                const requestData = () => {
                                    onRequestFilterData({
                                        filterParam:
                                            filterId as DataListOmniFilterParam,
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
                                onRequestNextPage(
                                    filterId as DataListOmniFilterParam,
                                )
                            }
                            showSelectedList
                            isCreatable
                            labelSelectedListHeader=''
                            labelListHeader='Filters'
                            {...OmniFilterProperties[filterId]
                                .filterComponentProps}
                        />
                    );
                })}

                <PortOmniFilter
                    key='port-omni-filter'
                    port={selectedValues.dest_port?.[0] ?? ''}
                    protocol={selectedValues.protocol?.[0] ?? ''}
                    selectedFilters={[
                        ...(selectedValues.dest_port ?? []),
                        ...(selectedValues.protocol ?? []),
                    ]}
                    onChange={({ protocol, port }) =>
                        onMultiChange({
                            [OmniFilterKeys.protocol]: protocol
                                ? [protocol]
                                : [],
                            [OmniFilterKeys.dest_port]: port ? [port] : [],
                        })
                    }
                    filterId={CustomOmniFilterKeys.dest_port}
                    filterLabel={
                        OmniFilterProperties[OmniFilterKeys.dest_port].label
                    }
                />

                <ActionOmniFilter
                    filterId={CustomOmniFilterKeys.action}
                    filterLabel={
                        OmniFilterProperties[CustomOmniFilterKeys.action].label
                    }
                    value={{
                        action: selectedValues.action?.[0],
                        staged_action: selectedValues.staged_action?.[0],
                    }}
                    selectedFilters={[
                        ...(selectedValues.action ?? []),
                        ...(selectedValues.staged_action ?? []),
                    ]}
                    onChange={({ action, staged_action }) =>
                        onMultiChange({
                            [OmniFilterKeys.action]: action ? [action] : [],
                            [OmniFilterKeys.staged_action]: staged_action
                                ? [staged_action]
                                : [],
                        })
                    }
                />

                <StartTimeOmniFilter
                    filterId={CustomOmniFilterKeys.start_time}
                    filterLabel={
                        OmniFilterProperties[CustomOmniFilterKeys.start_time]
                            .label
                    }
                    selectedFilters={selectedValues.start_time ?? null}
                    value={startTime.toString()}
                    onChange={handleChange}
                    onReset={() => handleClear(CustomOmniFilterKeys.start_time)}
                />
            </OmniFilterList>
        </>
    );
};

export default OmniFilters;
