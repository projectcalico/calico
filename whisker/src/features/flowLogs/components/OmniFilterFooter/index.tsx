import { OmniFilterFooter } from '@/libs/tigera/ui-components/components/common/OmniFilter/parts';
import { Button, ButtonProps } from '@chakra-ui/react';

type OmniFilterFooterProps = {
    testId: string;
    clearButtonProps: ButtonProps;
    submitButtonProps: ButtonProps;
};

const FilterFooter: React.FC<OmniFilterFooterProps> = ({
    testId,
    clearButtonProps,
    submitButtonProps,
}) => (
    <OmniFilterFooter data-testid={`${testId}-popover-footer`}>
        <Button variant='ghost' {...clearButtonProps}>
            {clearButtonProps.children ?? 'Clear'}
        </Button>
        <Button ml='auto' {...submitButtonProps}>
            {submitButtonProps.children ?? 'Update'}
        </Button>
    </OmniFilterFooter>
);

export default FilterFooter;
