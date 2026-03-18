import { CloseIcon } from '@chakra-ui/icons';
import {
    FormLabel,
    FormLabelProps,
    Tooltip,
    IconButton,
} from '@chakra-ui/react';
import { iconButtonStyles, labelStyles } from './styles';

type ClearableFormLabelProps = {
    showClearButton?: boolean;
    onClear: () => void;
    clearButtonAriaLabel: string;
} & FormLabelProps;

const ClearableFormLabel: React.FC<ClearableFormLabelProps> = ({
    showClearButton = false,
    onClear,
    clearButtonAriaLabel,
    ...props
}) => (
    <FormLabel {...labelStyles} {...props}>
        {props.children}
        {showClearButton && (
            <Tooltip label='Clear' placement='right' hasArrow>
                <IconButton
                    {...iconButtonStyles}
                    variant='icon'
                    icon={<CloseIcon />}
                    onClick={onClear}
                    aria-label={clearButtonAriaLabel}
                />
            </Tooltip>
        )}
    </FormLabel>
);

export default ClearableFormLabel;
