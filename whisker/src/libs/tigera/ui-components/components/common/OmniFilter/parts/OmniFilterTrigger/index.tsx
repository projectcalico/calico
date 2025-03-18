import { ChevronDownIcon } from '@chakra-ui/icons';
import {
    Badge,
    Button,
    ButtonProps,
    PopoverTrigger,
    SystemStyleObject,
    Text,
} from '@chakra-ui/react';
import { OperatorType } from '../../types';
import { useStyles } from '../OmniFilterContainer';

type OmniFilterTriggerProps = Partial<{
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
}: OmniFilterTriggerProps) => {
    const styles = useStyles();

    return (
        <PopoverTrigger>
            <Button
                variant='solidAlt'
                aria-expanded={isOpen}
                rightIcon={
                    showButtonIcon ? (
                        <ChevronDownIcon
                            fontSize={'lg'}
                            data-testid={`${testId}-button-chevron-icon`}
                        />
                    ) : undefined
                }
                data-testid={`${testId}-button-trigger`}
                onClick={onClick}
                {...(isActive && (styles.triggerActive as ButtonProps))}
                isDisabled={isDisabled}
            >
                {label}{' '}
                {isActive && showSelectedValueLabel && (
                    <>
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
                        {badgeLabel && (
                            <Badge variant='rounded' ml={1}>
                                +{badgeLabel}
                            </Badge>
                        )}
                    </>
                )}
            </Button>
        </PopoverTrigger>
    );
};

export default OmniFilterTrigger;
