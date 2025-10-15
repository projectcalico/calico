import { useDebouncedCallback, useFeature } from '@/hooks';
import {
    OmniFilter,
    OmniFilterList,
} from '@/libs/tigera/ui-components/components/common';
import { OmniFilterChangeEvent } from '@/libs/tigera/ui-components/components/common/OmniFilter';
import PortOmniFilter from '@/features/flowLogs/components/PortOmniFilter';
import { OmniFilterDataQuery } from '@/types/api';
import {
    DataListOmniFilterParam,
    OmniFilterProperties,
    ListOmniFiltersData,
    SelectedOmniFilterOptions,
    SelectedOmniFilters,
    OmniFilterKeys,
    CustomOmniFilterKeys,
    ListOmniFilterKeys,
    FilterKey,
} from '@/utils/omniFilter';
import React from 'react';
import PolicyOmniFilter from '../PolicyOmniFilter';
import StartTimeOmniFilter from '../StartTimeOmniFilter';
import ActionOmniFilter from '../ActionOmniFilter';

const listOmniFilterIds = Object.values(ListOmniFilterKeys);

const omniFilterIds = [
    ...listOmniFilterIds,
    ...Object.values(CustomOmniFilterKeys),
];

type OmniFiltersProps = {
    onChange: (event: OmniFilterChangeEvent) => void;
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
    const showFiltersV2 = useFeature('fitlersV2');
    const handleClear = (filterId: string) =>
        onChange({
            filterId: filterId,
            filterLabel: '',
            filters: [],
            operator: undefined,
        });

    const debounce = useDebouncedCallback();
    const [isLoading, setIsLoading] = React.useState(false);

    const policyV2Filters = React.useMemo(
        () =>
            [
                selectedValues.policyV2,
                selectedValues.policyV2Namespace,
                selectedValues.policyV2Tier,
                selectedValues.policyV2Kind,
            ]
                .filter(Boolean)
                .flat() as string[],
        [
            selectedValues.policyV2?.length,
            selectedValues.policyV2Namespace?.length,
            selectedValues.policyV2Tier?.length,
            selectedValues.policyV2Kind?.length,
        ],
    );

    return (
        <>
            <OmniFilterList
                gap={2}
                defaultFilterIds={omniFilterIds}
                visibleFilterIds={omniFilterIds}
                onChangeVisible={() => undefined}
                onResetVisible={onReset}
            >
                {showFiltersV2 && (
                    <PolicyOmniFilter
                        key='policy-omni-filter-v2'
                        onChange={onMultiChange}
                        filterId={CustomOmniFilterKeys.policyV2}
                        filterLabel={
                            OmniFilterProperties[OmniFilterKeys.policyV2].label
                        }
                        selectedValues={{
                            policyV2: selectedValues.policyV2,
                            policyV2Namespace: selectedValues.policyV2Namespace,
                            policyV2Tier: selectedValues.policyV2Tier,
                            policyV2Kind: selectedValues.policyV2Kind,
                        }}
                        selectedFilters={policyV2Filters}
                        filterQuery={selectedValues}
                    />
                )}

                {listOmniFilterIds.map((id) => {
                    const filterId = id as DataListOmniFilterParam;
                    return (
                        <OmniFilter
                            key={filterId}
                            filterId={filterId}
                            filterLabel={OmniFilterProperties[filterId].label}
                            filters={omniFilterData[filterId]?.filters ?? []}
                            selectedFilters={selectedListOmniFilters[filterId]}
                            onChange={onChange}
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
                        pending_action: selectedValues.pending_action?.[0],
                    }}
                    selectedFilters={[
                        ...(selectedValues.action ?? []),
                        ...(selectedValues.staged_action ?? []),
                        ...(selectedValues.pending_action ?? []),
                    ]}
                    onChange={({ action, staged_action, pending_action }) =>
                        onMultiChange({
                            [OmniFilterKeys.action]: action ? [action] : [],
                            [OmniFilterKeys.staged_action]: staged_action
                                ? [staged_action]
                                : [],
                            [OmniFilterKeys.pending_action]: pending_action
                                ? [pending_action]
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
                    onChange={onChange}
                    onClear={() => handleClear(CustomOmniFilterKeys.start_time)}
                />
            </OmniFilterList>
        </>
    );
};

export default OmniFilters;
