import Badge from '@/libs/tigera/ui-components/components/common/OmniFilter/components/Badge';
import {
    OmniFilterBody,
    OmniFilterContainer,
    OmniFilterContent,
    OmniFilterTrigger,
} from '@/libs/tigera/ui-components/components/common/OmniFilter/parts';
import { FilterKey, OmniFilterProperties } from '@/utils/omniFilter';
import { Flex, Text } from '@chakra-ui/react';
import React from 'react';
import OmniFilterFooter from '../OmniFilterFooter';
import QueryList, { PolicyFilterKey, PolicyQuery } from './QueryList';
import NoPolicyCheckbox from './NoPolicyCheckbox';
import { transformToFilterOptions, transformToQueries } from './utils';

export type PolicyFilter = Partial<Record<PolicyFilterKey, string>>;

const NO_POLICY_KIND = 'Profile';
const NO_POLICY_VALUE = `[{"kind": "${NO_POLICY_KIND}"}]`;

const checkIsNoPolicy = (selectedValues: PolicyFilter[]) =>
    selectedValues.length === 1 &&
    Object.keys(selectedValues[0]).length === 1 &&
    selectedValues[0].kind === NO_POLICY_KIND;

type PolicyOmniFilterProps = {
    onChange: (filterId: FilterKey, value: string) => void;
    onClear: () => void;
    selectedFilters: PolicyFilter[];
    filterId: FilterKey;
};

const testId = 'policy-omni-filter';
const PolicyOmniFilter: React.FC<PolicyOmniFilterProps> = ({
    onChange,
    onClear,
    selectedFilters,
}) => {
    const isNoPolicy = checkIsNoPolicy(selectedFilters);
    const [noPolicyChecked, setNoPolicyChecked] = React.useState(isNoPolicy);
    const [queryState, setQueryState] = React.useState<PolicyQuery[]>(
        isNoPolicy ? [] : transformToQueries(selectedFilters),
    );
    const filterCount = selectedFilters.length;
    const isActive = filterCount > 0;

    const handleChange = () => {
        const filterOptions = transformToFilterOptions(queryState);

        if (noPolicyChecked) {
            onChange(FilterKey.policy, NO_POLICY_VALUE);
        } else {
            onChange(
                FilterKey.policy,
                filterOptions.length ? JSON.stringify(filterOptions) : '',
            );
        }
    };

    const onClearFilter = (onClose: () => void) => {
        onClose();
        onClear();
    };

    const handleTriggerClick = React.useCallback(() => {
        if (isNoPolicy) {
            setNoPolicyChecked(true);
        } else {
            setQueryState(transformToQueries(selectedFilters));
        }
    }, [isNoPolicy, selectedFilters]);

    return (
        <OmniFilterContainer>
            {({ onClose }) => (
                <>
                    <OmniFilterTrigger
                        label={OmniFilterProperties[FilterKey.policy].label}
                        testId={testId}
                        onClick={handleTriggerClick}
                        isActive={isActive}
                        customContent={
                            <Flex>
                                <Text>Policy</Text>
                                {isActive && (
                                    <Badge ml={2}>{filterCount}</Badge>
                                )}
                            </Flex>
                        }
                    />
                    <OmniFilterContent
                        width={noPolicyChecked ? '300px' : '800px'}
                    >
                        <OmniFilterBody
                            p={4}
                            display='flex'
                            flexDirection='column'
                            gap={4}
                        >
                            {!noPolicyChecked && (
                                <>
                                    <QueryList
                                        queries={queryState}
                                        onChange={setQueryState}
                                    />

                                    <hr />
                                </>
                            )}

                            <NoPolicyCheckbox
                                value={noPolicyChecked}
                                onChange={setNoPolicyChecked}
                            />
                        </OmniFilterBody>

                        <OmniFilterFooter
                            testId={testId}
                            leftButtonProps={{
                                onClick: () => onClearFilter(onClose),
                                children: 'Clear all',
                            }}
                            rightButtonProps={{
                                onClick: () => {
                                    onClose();
                                    handleChange();
                                },
                            }}
                        />
                    </OmniFilterContent>
                </>
            )}
        </OmniFilterContainer>
    );
};

export default PolicyOmniFilter;
