import { Badge as ChakraBadge, BadgeProps } from '@chakra-ui/react';

const Badge: React.FC<React.PropsWithChildren & BadgeProps> = ({
    children,
    ...rest
}) => (
    <ChakraBadge variant='rounded' ml={1} {...rest}>
        +{children}
    </ChakraBadge>
);

export default Badge;
