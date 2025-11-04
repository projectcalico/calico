import {
    Tabs,
    TabsContent,
    TabsList,
    TabsTrigger,
} from '@/components/common/Tabs';
import { OmniFilterChangeEvent } from '@/libs/tigera/ui-components/components/common/OmniFilter';
import Badge from '@/libs/tigera/ui-components/components/common/OmniFilter/components/Badge';
import { FilterHintValues } from '@/types/render';
import {
    FilterHintKey,
    FilterKey,
    OmniFilterProperties,
    SelectedOmniFilters,
} from '@/utils/omniFilter';
import { Text } from '@chakra-ui/react';
import React from 'react';
import FilterChecklist from '../../FilterChecklist';

const filters = [
    FilterKey.policy,
    FilterKey.policyNamespace,
    FilterKey.policyTier,
    FilterKey.policyKind,
] as const;
export type PolicyFilters = (typeof filters)[number];

type FilterTabsProps = {
    filterId: FilterKey;
    values: Record<PolicyFilters, string[] | undefined>;
    filterQuery: SelectedOmniFilters;
    onChange: (event: OmniFilterChangeEvent) => void;
    onClear: (filterId: FilterHintKey) => void;
};

const FilterTabs: React.FC<FilterTabsProps> = ({
    values,
    filterQuery,
    onChange,
    onClear,
}) => (
    <Tabs
        variant='vertical'
        className='w-full !h-full'
        defaultValue={filters[0]}
    >
        <TabsList>
            {filters.map((filterId) => (
                <TabsTrigger
                    key={filterId}
                    value={filterId}
                    className='!justify-between items-center'
                >
                    <Text>{OmniFilterProperties[filterId].label}</Text>

                    {values[filterId]?.length ? (
                        <Badge
                            bg='tigeraGoldMedium40'
                            color='tigeraBlack'
                            fontSize='xs'
                            mr={1}
                            showPlus={false}
                            px={1.5}
                        >
                            {values[filterId].length}
                        </Badge>
                    ) : null}
                </TabsTrigger>
            ))}
        </TabsList>

        {filters.map((filterId) => (
            <TabsContent key={filterId} value={filterId}>
                <FilterChecklist
                    testId={filterId}
                    filterId={filterId}
                    label={OmniFilterProperties[filterId].label}
                    selectedValues={values[filterId] ?? []}
                    filterQuery={
                        {
                            ...filterQuery,
                            ...values,
                        } as FilterHintValues
                    }
                    onChange={onChange}
                    onClear={onClear}
                />
            </TabsContent>
        ))}
    </Tabs>
);

export default FilterTabs;
