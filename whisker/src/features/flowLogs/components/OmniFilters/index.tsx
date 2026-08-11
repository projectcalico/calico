import PortOmniFilter from '@/features/flowLogs/components/PortOmniFilter';
import { useFlowLogsUrlFilters } from '@/hooks/useFlowLogsUrlFilters';
import { OmniFilterList } from '@/libs/tigera/ui-components/components/common';
import { OmniFilterChangeEvent } from '@/libs/tigera/ui-components/components/common/OmniFilter';
import { parseStartTime } from '@/utils';
import {
    CustomOmniFilterKeys,
    FilterKey,
    ListOmniFilterKeys,
    OmniFilterKeys,
    OmniFilterProperties,
} from '@/utils/omniFilter';
import React from 'react';
import ActionOmniFilter from '../ActionOmniFilter';
import ListOmniFilter from '../ListOmniFilter';
import PolicyOmniFilter from '../PolicyOmniFilter';
import StartTimeOmniFilter from '../StartTimeOmniFilter';

const listOmniFilterIds = Object.values(ListOmniFilterKeys);

const omniFilterIds = [
    ...listOmniFilterIds,
    ...Object.values(CustomOmniFilterKeys),
];

const OmniFilters: React.FC = () => {
    const {
        filters: selectedValues,
        setFilter,
        setMultiFilter,
        clearFilters,
    } = useFlowLogsUrlFilters();

    const startTime = parseStartTime(selectedValues.start_time?.[0]);

    const handleClear = (filterId: string) => setFilter(filterId, []);

    const handleChange = (event: OmniFilterChangeEvent) =>
        setFilter(
            event.filterId,
            event.filters.map((filter) => filter.value),
        );

    const handlePolicyFilterChange = (filterId: string, value: string) =>
        setFilter(filterId, value ? [value] : null);

    return (
        <>
            <OmniFilterList
                gap={2}
                defaultFilterIds={omniFilterIds}
                visibleFilterIds={omniFilterIds}
                onChangeVisible={() => undefined}
                onResetVisible={clearFilters}
            >
                <PolicyOmniFilter
                    key='policy-omni-filter'
                    onChange={handlePolicyFilterChange}
                    filterId={CustomOmniFilterKeys.policy}
                    selectedFilters={selectedValues.policy ?? []}
                    onClear={() => handleClear(FilterKey.policy)}
                />

                {listOmniFilterIds.map((filterId) => (
                    <ListOmniFilter
                        key={filterId}
                        filterId={filterId}
                        filterLabel={OmniFilterProperties[filterId].label}
                        selectedFilters={(selectedValues[filterId] ?? []).map(
                            (value) => ({ label: value, value }),
                        )}
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
                        setMultiFilter({
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
                        setMultiFilter({
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
