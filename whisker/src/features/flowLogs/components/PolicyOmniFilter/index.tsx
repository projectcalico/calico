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
import { Flex, Text } from '@chakra-ui/react';
import React from 'react';
import OmniFilterFooter from '../OmniFilterFooter';
import FilterTabs, { PolicyFilters } from './FilterTabs';

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
            policy: [],
            policyNamespace: [],
            policyTier: [],
            policyKind: [],
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
                        label={OmniFilterProperties[FilterKey.policy].label}
                        isDisabled={false}
                        testId={testId}
                        onClick={() => setValues(selectedValues)}
                        isActive={isActive}
                        customContent={
                            <Flex>
                                <Text>
                                    {
                                        OmniFilterProperties[FilterKey.policy]
                                            .label
                                    }
                                </Text>
                                {isActive && (
                                    <Badge ml={2}>{filterCount}</Badge>
                                )}
                            </Flex>
                        }
                    />
                    <OmniFilterContent width='600px'>
                        <OmniFilterBody p={0}>
                            <FilterTabs
                                filterId={FilterKey.policy}
                                values={values}
                                filterQuery={filterQuery}
                                onChange={handleChange}
                                onClear={handleClear}
                            />
                        </OmniFilterBody>

                        <OmniFilterFooter
                            testId={testId}
                            clearButtonProps={{
                                onClick: () => onClearFilter(onClose),
                                children: 'Clear all',
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
