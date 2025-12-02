import { OmniFilterFooter } from '@/libs/tigera/ui-components/components/common/OmniFilter/parts';
import { Button, ButtonProps } from '@chakra-ui/react';

type OmniFilterFooterProps = {
    testId: string;
    leftButtonProps?: ButtonProps;
    rightButtonProps?: ButtonProps;
};

const FilterFooter: React.FC<OmniFilterFooterProps> = ({
    testId,
    leftButtonProps,
    rightButtonProps,
}) => (
    <OmniFilterFooter data-testid={`${testId}-popover-footer`}>
        {leftButtonProps && (
            <Button variant='ghost' {...leftButtonProps}>
                {leftButtonProps.children ?? 'Clear'}
            </Button>
        )}
        {rightButtonProps && (
            <Button ml='auto' {...rightButtonProps}>
                {rightButtonProps.children ?? 'Update'}
            </Button>
        )}
    </OmniFilterFooter>
);

export default FilterFooter;
