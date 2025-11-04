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
import {
    Accordion,
    AccordionButton,
    AccordionIcon,
    AccordionItem,
    AccordionPanel,
    Box,
    Flex,
    FormControl,
    Text,
    useDisclosure,
} from '@chakra-ui/react';
import React from 'react';
import OmniFilterFooter from '../OmniFilterFooter';
import { radioOptions } from './options';
import { radioStyles } from './styles';

const testId = 'action-omni-filter';

type ActionKeys =
    | FilterKey.action
    | FilterKey.staged_action
    | FilterKey.pending_action;

type ActionOmniFilterProps = {
    onChange: (event: {
        action: string | undefined;
        staged_action: string | undefined;
        pending_action: string | undefined;
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
        pending_action: value.pending_action ?? '',
    });
    const [reduceMotion, setReduceMotion] = React.useState(false);
    const { isOpen, onClose, onToggle } = useDisclosure({
        onClose: () => setReduceMotion(true),
        onOpen: () => {
            setActions({
                action: value.action ?? '',
                staged_action: value.staged_action ?? '',
                pending_action: value.pending_action ?? '',
            });
        },
    });

    const filterCount = Object.values(value).flat().filter(Boolean).length;
    const isActive = filterCount > 0;

    // needed because of chakra bug
    React.useEffect(() => {
        setReduceMotion(!isOpen);
    }, [isOpen]);

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
                <OmniFilterBody py={4}>
                    <FormControl>
                        <FormLabel
                            showClearButton={!!actions.action}
                            onClear={() => handleClear(FilterKey.action)}
                            clearButtonAriaLabel='Clear Action'
                            htmlFor={FilterKey.action}
                        >
                            Action
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
                            Staged Action
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

                    <Accordion
                        mt={2}
                        allowMultiple
                        defaultIndex={actions.pending_action ? [0] : undefined}
                        reduceMotion={reduceMotion}
                    >
                        <AccordionItem border='none'>
                            <AccordionButton px={0}>
                                <Box
                                    as='span'
                                    flex='1'
                                    textAlign='left'
                                    color='tigeraGrey.200'
                                    fontSize='sm'
                                >
                                    More filters
                                </Box>
                                <AccordionIcon />
                            </AccordionButton>

                            <AccordionPanel p={0}>
                                <FormControl>
                                    <FormLabel
                                        showClearButton={
                                            !!actions.pending_action
                                        }
                                        onClear={() =>
                                            handleClear(
                                                FilterKey.pending_action,
                                            )
                                        }
                                        clearButtonAriaLabel='Clear Pending Action'
                                        htmlFor={FilterKey.pending_action}
                                    >
                                        Pending Action
                                    </FormLabel>
                                    <RadioToggle
                                        value={actions.pending_action}
                                        name={FilterKey.pending_action}
                                        onChange={(pending_action) =>
                                            handleChange(
                                                FilterKey.pending_action,
                                                pending_action,
                                            )
                                        }
                                        options={radioOptions}
                                        containerStyles={radioStyles}
                                        testId='radio-toggle-pending_action'
                                    />
                                </FormControl>
                            </AccordionPanel>
                        </AccordionItem>
                    </Accordion>
                </OmniFilterBody>
                <OmniFilterFooter
                    testId={testId}
                    clearButtonProps={{
                        onClick: () => {
                            onChange({
                                action: undefined,
                                staged_action: undefined,
                                pending_action: undefined,
                            });
                            onClose();
                        },
                    }}
                    submitButtonProps={{
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
