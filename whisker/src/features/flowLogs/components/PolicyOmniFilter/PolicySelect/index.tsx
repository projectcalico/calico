import { useOmniFilterOptions } from '@/hooks/omniFilters';
import OmniFilter, {
    OmniFilterChangeEvent,
} from '@/libs/tigera/ui-components/components/common/OmniFilter';
import { OmniFilterOption } from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import { SelectOption } from '@/libs/tigera/ui-components/components/common/Select';
import { DataFilterId } from '@/utils/filters/dataFilters';
import React from 'react';

type PolicySelectProps = {
    filterKey: DataFilterId;
    value: OmniFilterOption | null | undefined;
    onChange: (value: SelectOption | null) => void;
    showSearch?: boolean;
    placeholder: string;
};

const PolicySelect: React.FC<PolicySelectProps> = ({
    filterKey,
    value,
    onChange,
    showSearch = true,
    placeholder,
}) => {
    const {
        options,
        isLoading,
        total,
        requestOptions,
        requestSearch,
        requestNextPage,
    } = useOmniFilterOptions(filterKey, { narrowByActiveFilters: false });

    const handleChange = (change: OmniFilterChangeEvent) => {
        onChange(change.filters[0]);
    };

    const partsProps = React.useMemo(
        () => ({
            triggerProps: {
                isActive: false,
                buttonProps: {
                    width: 'full',
                    justifyContent: 'space-between',
                    py: '5',
                    bg: 'experimental-token-bg-input',
                    _hover: {
                        bg: 'experimental-token-bg-input',
                    },
                    _expanded: {
                        bg: 'experimental-token-bg-input',
                    },
                },
                customContent: value ? (
                    <p>{value.label}</p>
                ) : (
                    <p className='text-tigera-token-fg-subtle'>{placeholder}</p>
                ),
            },
        }),
        [value?.label],
    );

    return (
        <OmniFilter
            key={filterKey}
            filterId={filterKey}
            filterLabel=''
            filters={options ?? []}
            selectedFilters={value ? [value] : []}
            onChange={handleChange}
            onClear={() => onChange(null)}
            showOperatorSelect={false}
            listType='select'
            isLoading={isLoading}
            totalItems={total ?? 0}
            onReady={() => requestOptions('')}
            onRequestSearch={(_filterId, searchOption) =>
                requestSearch(searchOption)
            }
            onRequestMore={requestNextPage}
            showSelectedList
            isCreatable
            showSearch={showSearch}
            partsProps={partsProps}
            popoverContentProps={{
                width: '400px',
            }}
        />
    );
};

export default PolicySelect;
