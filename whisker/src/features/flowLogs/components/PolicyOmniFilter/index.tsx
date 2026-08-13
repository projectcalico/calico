import Badge from '@/libs/tigera/ui-components/components/common/OmniFilter/components/Badge';
import {
    OmniFilterBody,
    OmniFilterContainer,
    OmniFilterContent,
    OmniFilterTrigger,
} from '@/libs/tigera/ui-components/components/common/OmniFilter/parts';
import { Text } from '@/libs/tigera/ui-components/components/common/text';
import { PolicyFilter } from '@/utils/filters/types';
import { FilterKeys, UrlFilterKey } from '@/utils/filters/urlKeys';
import { Text as ChakraText, Flex } from '@chakra-ui/react';
import React from 'react';
import OmniFilterFooter from '../OmniFilterFooter';
import NoPolicyCheckbox from './NoPolicyCheckbox';
import QueryList, { PolicyQuery } from './QueryList';
import { transformToFilterOptions, transformToQueries } from './utils';

const NO_POLICY_KIND = 'Profile';
const NO_POLICY_VALUE = `[{"kind": "${NO_POLICY_KIND}"}]`;

const checkIsNoPolicy = (selectedValues: PolicyFilter[]) =>
    selectedValues.length === 1 &&
    Object.keys(selectedValues[0]).length === 1 &&
    selectedValues[0].kind === NO_POLICY_KIND;

type PolicyOmniFilterProps = {
    onChange: (filterId: UrlFilterKey, value: string) => void;
    onClear: () => void;
    selectedFilters: PolicyFilter[];
    filterId: UrlFilterKey;
    filterLabel: string;
};

const testId = 'policy-omni-filter';
const PolicyOmniFilter: React.FC<PolicyOmniFilterProps> = ({
    onChange,
    onClear,
    selectedFilters,
    filterLabel,
}) => {
    const isNoPolicy = checkIsNoPolicy(selectedFilters);
    const [noPolicyChecked, setNoPolicyChecked] = React.useState(isNoPolicy);
    const [queryState, setQueryState] = React.useState<PolicyQuery[]>(
        isNoPolicy ? [{}] : transformToQueries(selectedFilters),
    );
    const filterCount = selectedFilters.length;
    const isActive = filterCount > 0;

    const handleChange = () => {
        const filterOptions = transformToFilterOptions(queryState);

        if (noPolicyChecked) {
            onChange(FilterKeys.policy, NO_POLICY_VALUE);
        } else {
            onChange(
                FilterKeys.policy,
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
                        label={filterLabel}
                        testId={testId}
                        onClick={handleTriggerClick}
                        isActive={isActive}
                        customContent={
                            <Flex>
                                <ChakraText>{filterLabel}</ChakraText>
                                {isActive && (
                                    <Badge ml={2}>{filterCount}</Badge>
                                )}
                            </Flex>
                        }
                    />
                    <OmniFilterContent
                        width={noPolicyChecked ? '300px' : '850px'}
                    >
                        <OmniFilterBody
                            p={4}
                            display='flex'
                            flexDirection='column'
                            gap={4}
                        >
                            {!noPolicyChecked && (
                                <>
                                    <div>
                                        <Text size='base' className='font-bold'>
                                            Policy filter
                                        </Text>
                                        <span className=' text-tigera-token-fg-support text-sm'>
                                            Filter by policy attributes (kind,
                                            tier, namespace, name) using{' '}
                                            <span className='font-bold'>
                                                AND
                                            </span>
                                            . Multiple filters are combined
                                            using{' '}
                                            <span className='font-bold'>
                                                OR
                                            </span>
                                            .
                                        </span>
                                    </div>

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
                                    setQueryState([{}]);
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
