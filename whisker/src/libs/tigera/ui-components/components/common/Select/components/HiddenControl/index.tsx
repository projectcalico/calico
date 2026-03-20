import { VisuallyHidden } from '@chakra-ui/react';
import { components, ControlProps } from 'chakra-react-select';

const HiddenControl = (props: ControlProps<any, boolean>): JSX.Element => (
    <VisuallyHidden>
        <components.Control {...(props as any)} />
    </VisuallyHidden>
);

export default HiddenControl;
