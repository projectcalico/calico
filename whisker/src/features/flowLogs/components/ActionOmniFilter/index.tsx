import FormLabel from '@/components/common/FormLabel';
import RadioToggle from '@/components/common/RadioToggle';
import Badge from '@/libs/tigera/ui-components/components/common/OmniFilter/components/Badge';
import {
    OmniFilterBody,
    OmniFilterContainer,
    OmniFilterContent,
    OmniFilterTrigger,
} from '@/libs/tigera/ui-components/components/common/OmniFilter/parts';
import {
    CustomOmniFilterParam,
    FilterKey,
    OmniFilterProperties,
} from '@/utils/omniFilter';
import { InfoOutlineIcon } from '@chakra-ui/icons';
import {
    Flex,
    FormControl,
    Text,
    Tooltip,
    useDisclosure,
} from '@chakra-ui/react';
import React from 'react';
import OmniFilterFooter from '../OmniFilterFooter';
import { radioOptions } from './options';
import { radioStyles } from './styles';

const testId = 'action-omni-filter';

type ActionKeys = FilterKey.action | FilterKey.staged_action;

type ActionOmniFilterProps = {
    onChange: (event: {
        action: string | undefined;
        staged_action: string | undefined;
    }) => void;
    selectedFilters: string[];
    filterLabel: string;
    filterId: CustomOmniFilterParam;
    value: Record<ActionKeys, string | undefined>;
};

const ActionOmniFilter = ({ onChange, value }: ActionOmniFilterProps) => {
    const [actions, setActions] = React.useState({
        action: value.action ?? '',
        staged_action: value.staged_action ?? '',
    });

    const { isOpen, onClose, onToggle } = useDisclosure({
        onOpen: () => {
            setActions({
                action: value.action ?? '',
                staged_action: value.staged_action ?? '',
            });
        },
    });

    const filterCount = Object.values(value).flat().filter(Boolean).length;
    const isActive = filterCount > 0;

    const handleChange = React.useCallback(
        (key: ActionKeys, value: string) => {
            setActions((state) => ({ ...state, [key]: value }));
        },
        [setActions],
    );

    const handleClear = React.useCallback(
        (key: ActionKeys) => {
            handleChange(key, '');
        },
        [handleChange],
    );

    return (
        <OmniFilterContainer onClose={onClose} isOpen={isOpen}>
            <OmniFilterTrigger
                isOpen={isOpen}
                onClick={onToggle}
                label={OmniFilterProperties[FilterKey.action].label}
                isActive={isActive}
                testId={testId}
                selectedValueLabel=''
                customContent={
                    <Flex>
                        <Text>
                            {OmniFilterProperties[FilterKey.action].label}
                        </Text>
                        {isActive && <Badge ml={2}>{filterCount}</Badge>}
                    </Flex>
                }
            />

            <OmniFilterContent data-testid='action-omni-filter-content'>
                <OmniFilterBody p={4}>
                    <FormControl>
                        <FormLabel
                            showClearButton={!!actions.action}
                            onClear={() => handleClear(FilterKey.action)}
                            clearButtonAriaLabel='Clear Action'
                            htmlFor={FilterKey.action}
                        >
                            <Text lineHeight='1'>Action</Text>
                        </FormLabel>
                        <RadioToggle
                            name={FilterKey.action}
                            value={actions.action}
                            onChange={(action) =>
                                handleChange(FilterKey.action, action)
                            }
                            options={radioOptions}
                            containerStyles={radioStyles}
                            testId='radio-toggle-action'
                        />
                    </FormControl>

                    <FormControl mt={4}>
                        <FormLabel
                            showClearButton={!!actions.staged_action}
                            onClear={() => handleClear(FilterKey.staged_action)}
                            clearButtonAriaLabel='Clear Staged Action'
                            htmlFor={FilterKey.staged_action}
                        >
                            <Flex alignItems='center' gap={1}>
                                <Text lineHeight='1'>Staged Action</Text>
                                <Tooltip label='Filter by the action that would be applied if staged network policies were enforced now'>
                                    <InfoOutlineIcon boxSize={3} />
                                </Tooltip>
                            </Flex>
                        </FormLabel>

                        <RadioToggle
                            value={actions.staged_action}
                            name={FilterKey.staged_action}
                            onChange={(staged_action) =>
                                handleChange(
                                    FilterKey.staged_action,
                                    staged_action,
                                )
                            }
                            options={radioOptions}
                            containerStyles={radioStyles}
                            testId='radio-toggle-staged_action'
                        />
                    </FormControl>
                </OmniFilterBody>
                <OmniFilterFooter
                    testId={testId}
                    leftButtonProps={{
                        onClick: () => {
                            onChange({
                                action: undefined,
                                staged_action: undefined,
                            });
                            onClose();
                        },
                    }}
                    rightButtonProps={{
                        onClick: () => {
                            onChange(actions);
                            onClose();
                        },
                    }}
                />
            </OmniFilterContent>
        </OmniFilterContainer>
    );
};

export default ActionOmniFilter;
