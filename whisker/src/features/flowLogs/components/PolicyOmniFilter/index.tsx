import { OmniFilterChangeEvent } from '@/libs/tigera/ui-components/components/common/OmniFilter';
import Badge from '@/libs/tigera/ui-components/components/common/OmniFilter/components/Badge';
import {
    OmniFilterBody,
    OmniFilterContainer,
    OmniFilterContent,
    OmniFilterTrigger,
} from '@/libs/tigera/ui-components/components/common/OmniFilter/parts';
import {
    CustomOmniFilterParam,
    FilterHintKey,
    FilterKey,
    OmniFilterProperties,
    SelectedOmniFilters,
} from '@/utils/omniFilter';
import { Flex, FormControl, FormLabel, Text } from '@chakra-ui/react';
import React from 'react';
import PolicyListOmniFilter from '../TagListOmniFilter';
import { FilterHintValues } from '@/types/render';
import OmniFilterFooter from '../OmniFilterFooter';

const filters = [
    FilterKey.policyV2,
    FilterKey.policyV2Namespace,
    FilterKey.policyV2Tier,
    FilterKey.policyV2Kind,
] as const;
type PolicyFilters = (typeof filters)[number];

type PolicyOmniFilterProps = {
    onChange: (change: Partial<Record<FilterKey, string[]>>) => void;
    selectedValues: Record<PolicyFilters, string[] | undefined>;
    filterLabel: string;
    filterId: CustomOmniFilterParam;
    filterQuery: SelectedOmniFilters;
    selectedFilters: string[];
};

const testId = 'policy-omni-filter-v2';
const PolicyOmniFilter: React.FC<PolicyOmniFilterProps> = ({
    onChange,
    selectedValues,
    filterQuery,
}) => {
    const [values, setValues] =
        React.useState<Record<PolicyFilters, string[] | undefined>>(
            selectedValues,
        );

    const handleChange = (event: OmniFilterChangeEvent) => {
        setValues((prev) => ({
            ...prev,
            [event.filterId]: event.filters.map((filter) => filter.value),
        }));
    };

    const handleClear = (filterId: FilterHintKey) =>
        handleChange({
            filterId,
            filterLabel: '',
            filters: [],
            operator: undefined,
        });

    const onSubmitFilter = (onClose: () => void) => {
        onClose();
        onChange(values);
    };

    const onClearFilter = (onClose: () => void) => {
        onChange({
            policyV2: [],
            policyV2Namespace: [],
            policyV2Tier: [],
            policyV2Kind: [],
        });
        onClose();
    };

    const filterCount = Object.values(selectedValues)
        .flat()
        .filter(Boolean).length;
    const isActive = filterCount > 0;

    return (
        <OmniFilterContainer>
            {({ onClose }) => (
                <>
                    <OmniFilterTrigger
                        label={OmniFilterProperties[FilterKey.policyV2].label}
                        isDisabled={false}
                        testId={testId}
                        onClick={() => setValues(selectedValues)}
                        isActive={isActive}
                        customContent={
                            <Flex>
                                <Text>
                                    {
                                        OmniFilterProperties[FilterKey.policyV2]
                                            .label
                                    }
                                </Text>
                                {isActive && (
                                    <Badge ml={2}>{filterCount}</Badge>
                                )}
                            </Flex>
                        }
                    />
                    <OmniFilterContent width='500px'>
                        <OmniFilterBody py={4}>
                            {filters.map((filterId, index) => (
                                <FormControl
                                    mt={index === 0 ? 0 : 4}
                                    key={filterId}
                                >
                                    <FormLabel
                                        fontSize='sm'
                                        htmlFor={`${filterId}-taglist`}
                                    >
                                        {OmniFilterProperties[filterId].label}
                                    </FormLabel>
                                    <PolicyListOmniFilter
                                        filterId={filterId}
                                        label={
                                            OmniFilterProperties[filterId].label
                                        }
                                        selectedValues={values[filterId] ?? []}
                                        filterQuery={
                                            {
                                                ...filterQuery,
                                                ...values,
                                            } as FilterHintValues
                                        }
                                        onChange={handleChange}
                                        onClear={handleClear}
                                    />
                                </FormControl>
                            ))}
                        </OmniFilterBody>

                        <OmniFilterFooter
                            testId={testId}
                            clearButtonProps={{
                                onClick: () => onClearFilter(onClose),
                            }}
                            submitButtonProps={{
                                onClick: () => onSubmitFilter(onClose),
                            }}
                        />
                    </OmniFilterContent>
                </>
            )}
        </OmniFilterContainer>
    );
};

export default PolicyOmniFilter;
