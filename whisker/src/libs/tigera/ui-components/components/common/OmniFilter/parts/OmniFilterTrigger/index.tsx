import { ChevronDownIcon } from '@chakra-ui/icons';
import {
    Box,
    Button,
    ButtonProps,
    Divider,
    Flex,
    PopoverTrigger,
    SystemStyleObject,
    Text,
} from '@chakra-ui/react';
import { OperatorType } from '../../types';
import { useStyles } from '../OmniFilterContainer';
import Badge from '../../components/Badge';
import { X } from 'lucide-react';

export type OmniFilterTriggerProps = Partial<{
    isOpen: boolean;
    isActive: boolean;
    label: string;
    selectedValueLabel: string;
    selectedValueTitle: string;
    showSelectedValueLabel: boolean;
    valueSx: SystemStyleObject;
    badgeLabel: string | number;
    operator: string;
    showButtonIcon: boolean;
    isDisabled: boolean;
    testId: string;
    onClick: () => void;
    customContent?: React.ReactNode;
    buttonProps?: ButtonProps;
    showClearButton?: boolean;
    onClear?: () => void;
}>;

export const OmniFilterTrigger = ({
    isOpen = false,
    isActive = false,
    label,
    selectedValueLabel,
    selectedValueTitle,
    showSelectedValueLabel = true,
    valueSx,
    badgeLabel,
    operator = OperatorType.Equals,
    showButtonIcon = true,
    testId,
    onClick,
    isDisabled = false,
    customContent,
    buttonProps,
    showClearButton = false,
    onClear,
}: OmniFilterTriggerProps) => {
    const styles = useStyles();

    return (
        <PopoverTrigger>
            <Button
                variant='solidAlt'
                aria-expanded={isOpen}
                rightIcon={
                    showButtonIcon ? (
                        <Flex alignItems='center' gap={1}>
                            {showClearButton && (
                                <>
                                    <Box
                                        aria-label='Clear filter'
                                        data-testid='clear-filter-icon'
                                        role='button'
                                        p={1}
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            onClear?.();
                                        }}
                                        _hover={{
                                            color: 'experimental-token-fg-support',
                                        }}
                                        _active={{
                                            color: 'experimental-token-fg-subtle',
                                        }}
                                    >
                                        <X size='14' />
                                    </Box>
                                    <Divider orientation='vertical' />
                                </>
                            )}

                            <ChevronDownIcon
                                fontSize={'lg'}
                                data-testid={`${testId}-button-chevron-icon`}
                                role='button'
                                minW='20px'
                            />
                        </Flex>
                    ) : undefined
                }
                data-testid={`${testId}-button-trigger`}
                onClick={onClick}
                {...(isActive && (styles.triggerActive as ButtonProps))}
                isDisabled={isDisabled}
                {...buttonProps}
            >
                {customContent ?? (
                    <Flex>
                        {label}{' '}
                        {isActive && showSelectedValueLabel && (
                            <Text
                                isTruncated
                                data-testid={`${testId}-button-text`}
                                title={selectedValueTitle}
                                sx={{
                                    ...styles.triggerText,
                                    ...valueSx,
                                }}
                            >
                                {operator} {selectedValueLabel}
                            </Text>
                        )}
                        {badgeLabel && <Badge ml={1}>{badgeLabel}</Badge>}
                    </Flex>
                )}
            </Button>
        </PopoverTrigger>
    );
};

export default OmniFilterTrigger;
