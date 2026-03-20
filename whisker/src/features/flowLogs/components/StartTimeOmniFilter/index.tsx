import { OmniFilterChangeEvent } from '@/libs/tigera/ui-components/components/common/OmniFilter';
import { OmniFilterOption } from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import { CustomOmniFilterParam } from '@/utils/omniFilter';
import React from 'react';
import StartTimeFilter from './components/StartTimeFilter';

const DEFAULT_VALUE = '1';
const options = [
    { label: 'Now', value: '0' },
    { label: 'Last 1 minute', value: '1' },
    { label: 'Last 5 minutes', value: '5' },
    { label: 'Last 10 minutes', value: '10' },
    { label: 'Last 15 minutes', value: '15' },
    { label: 'Last 20 minutes', value: '20' },
    { label: 'Last 25 minutes', value: '25' },
    { label: 'Last 30 minutes', value: '30' },
    { label: 'Last 35 minutes', value: '35' },
    { label: 'Last 40 minutes', value: '40' },
    { label: 'Last 45 minutes', value: '45' },
    { label: 'Last 50 minutes', value: '50' },
    { label: 'Last 55 minutes', value: '55' },
    { label: 'Last hour', value: '60' },
];

type StartTimeOmniFilterProps = {
    selectedFilters: string[] | null;
    filterLabel: string;
    filterId: CustomOmniFilterParam;
    onChange: (event: OmniFilterChangeEvent) => void;
    onReset: () => void;
    value: string;
};

const StartTimeOmniFilter: React.FC<StartTimeOmniFilterProps> = ({
    value,
    onChange,
    onReset,
    filterId,
    filterLabel,
}) => {
    const initialValue = React.useMemo(
        () => options.find((option) => option.value === value),
        [value],
    )!;
    const [startTime, setStartTime] =
        React.useState<OmniFilterOption>(initialValue);

    const handleChange = (change: OmniFilterOption) => {
        if (initialValue.value !== change.value) {
            onChange({
                filterId: filterId,
                filterLabel: filterLabel,
                filters: [change],
                operator: undefined,
            });
        }
    };

    return (
        <StartTimeFilter
            filterLabel={filterLabel}
            value={startTime}
            triggerLabel={initialValue.label}
            isActive={!!value}
            onChange={handleChange}
            onReset={onReset}
            onClick={() => setStartTime(initialValue!)}
            options={options}
            hasChanged={initialValue.value !== DEFAULT_VALUE}
        />
    );
};

export default StartTimeOmniFilter;
