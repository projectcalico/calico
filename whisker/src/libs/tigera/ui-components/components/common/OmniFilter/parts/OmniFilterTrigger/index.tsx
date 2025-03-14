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
    valueLabel: string;
    valueTitle: string;
    customValueLabel: string;
    valueSx: SystemStyleObject;
    badgeLabel: string;
    operator: OperatorType;
    showButtonIcon: boolean;
    isDisabled: boolean;
    testId: string;
    onClick: () => void;
}>;

export const OmniFilterTrigger = ({
    isOpen = false,
    isActive = false,
    label,
    valueLabel,
    valueTitle,
    valueSx,
    customValueLabel,
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
                {customValueLabel ? (
                    <Text
                        isTruncated
                        data-testid={`${testId}-button-text`}
                        sx={{
                            ...styles.triggerText,
                            ...valueSx,
                        }}
                    >
                        {customValueLabel}
                    </Text>
                ) : valueLabel ? (
                    <>
                        <Text
                            isTruncated
                            data-testid={`${testId}-button-text`}
                            title={valueTitle}
                            sx={{
                                ...styles.triggerText,
                                ...valueSx,
                            }}
                        >
                            {operator} {valueLabel}
                        </Text>
                        {badgeLabel && (
                            <Badge variant='rounded' ml={1}>
                                +{badgeLabel}
                            </Badge>
                        )}
                    </>
                ) : null}
            </Button>
        </PopoverTrigger>
    );
};

export default OmniFilterTrigger;
