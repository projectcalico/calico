import PortOmniFilter from '@/features/flowLogs/components/PortOmniFilter';
import { useFlowLogsUrlFilters } from '@/hooks/useFlowLogsUrlFilters';
import { OmniFilterList } from '@/libs/tigera/ui-components/components/common';
import { OmniFilterChangeEvent } from '@/libs/tigera/ui-components/components/common/OmniFilter';
import { FilterKeys } from '@/utils/filters/urlKeys';
import React from 'react';
import ActionOmniFilter from '../ActionOmniFilter';
import ListOmniFilter from '../ListOmniFilter';
import PolicyOmniFilter from '../PolicyOmniFilter';
import ReporterOmniFilter from '../ReporterOmniFilter';
import StartTimeOmniFilter from '../StartTimeOmniFilter';
import {
    tableLevelFilterIds,
    tableLevelDataFilterIds,
    filterLabels,
} from './filters';

const TableFilters: React.FC = () => {
    const {
        filters: selectedValues,
        startTime,
        setFilter,
        setMultiFilter,
        clearFilters,
    } = useFlowLogsUrlFilters();

    const handleClear = (filterId: string) => setFilter(filterId, []);

    const handleChange = (event: OmniFilterChangeEvent) =>
        setFilter(
            event.filterId,
            event.filters.map((filter) => filter.value),
        );

    const handlePolicyFilterChange = (filterId: string, value: string) =>
        setFilter(filterId, value ? [value] : null);

    return (
        <OmniFilterList
            data-testid='table-filters'
            gap={2}
            defaultFilterIds={[...tableLevelFilterIds]}
            visibleFilterIds={[...tableLevelFilterIds]}
            onChangeVisible={() => undefined}
            onResetVisible={clearFilters}
        >
            <PolicyOmniFilter
                key='policy-omni-filter'
                onChange={handlePolicyFilterChange}
                filterId={FilterKeys.policy}
                filterLabel={filterLabels.policy}
                selectedFilters={selectedValues.policy ?? []}
                onClear={() => handleClear(FilterKeys.policy)}
            />

            {tableLevelDataFilterIds.map((filterId) => (
                <ListOmniFilter
                    key={filterId}
                    filterId={filterId}
                    filterLabel={filterLabels[filterId]}
                    selectedFilters={(selectedValues[filterId] ?? []).map(
                        (value) => ({ label: value, value }),
                    )}
                />
            ))}

            <ReporterOmniFilter
                key='reporter-omni-filter'
                filterId={FilterKeys.reporter}
                filterLabel={filterLabels.reporter}
                selectedFilters={(selectedValues.reporter ?? []).map(
                    (value) => ({ label: value, value }),
                )}
            />

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
                        protocol: protocol ? [protocol] : [],
                        dest_port: port ? [port] : [],
                    })
                }
                filterId={FilterKeys.dest_port}
                filterLabel={filterLabels.dest_port}
            />

            <ActionOmniFilter
                filterId={FilterKeys.action}
                filterLabel={filterLabels.action}
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
                        action: action ? [action] : [],
                        staged_action: staged_action ? [staged_action] : [],
                    })
                }
            />

            <StartTimeOmniFilter
                filterId={FilterKeys.start_time}
                filterLabel={filterLabels.start_time}
                selectedFilters={selectedValues.start_time ?? null}
                value={startTime.toString()}
                onChange={handleChange}
                onReset={() => handleClear(FilterKeys.start_time)}
            />
        </OmniFilterList>
    );
};

export default TableFilters;
