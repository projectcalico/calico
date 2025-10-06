import { OmniFilterChangeEvent } from '@/libs/tigera/ui-components/components/common/OmniFilter';
import { OmniFilterOption } from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import { CustomOmniFilterParam } from '@/utils/omniFilter';
import React from 'react';
import StartTimeFilter from './components/StartTimeFilter';

const options = [
    { label: 'Now', value: '0' },
    { label: '1 minute ago', value: '1' },
    { label: '5 minutes ago', value: '5' },
    { label: '10 minutes ago', value: '10' },
    { label: '15 minutes ago', value: '15' },
    { label: '20 minutes ago', value: '20' },
    { label: '25 minutes ago', value: '25' },
    { label: '30 minutes ago', value: '30' },
    { label: '35 minutes ago', value: '35' },
    { label: '40 minutes ago', value: '40' },
    { label: '45 minutes ago', value: '45' },
    { label: '50 minutes ago', value: '50' },
    { label: '55 minutes ago', value: '55' },
    { label: '1 hour ago', value: '60' },
];

type StartTimeOmniFilterProps = {
    selectedFilters: string[] | null;
    filterLabel: string;
    filterId: CustomOmniFilterParam;
    onChange: (event: OmniFilterChangeEvent) => void;
    onClear: () => void;
    value: string;
};

const StartTimeOmniFilter: React.FC<StartTimeOmniFilterProps> = ({
    value,
    onChange,
    onClear,
    filterId,
    filterLabel,
}) => {
    const initialValue = React.useMemo(
        () => options.find((option) => option.value === value),
        [value],
    )!;
    const [startTime, setStartTime] =
        React.useState<OmniFilterOption>(initialValue);

    const handleClear = () => {
        onClear();
    };

    const handleChange = () => {
        if (initialValue.value !== startTime.value) {
            onChange({
                filterId: filterId,
                filterLabel: filterLabel,
                filters: [startTime],
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
            onChange={setStartTime}
            onClear={handleClear}
            onClick={() => setStartTime(initialValue!)}
            onSubmit={handleChange}
            options={options}
        />
    );
};

export default StartTimeOmniFilter;
