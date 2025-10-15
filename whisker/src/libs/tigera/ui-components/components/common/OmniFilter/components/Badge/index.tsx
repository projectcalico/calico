import { Badge as ChakraBadge, BadgeProps } from '@chakra-ui/react';

const Badge: React.FC<React.PropsWithChildren & BadgeProps> = ({
    children,
    ...rest
}) => (
    <ChakraBadge
        ml={1}
        variant='solid'
        color='tigeraLightBlue'
        fontSize='sm'
        {...rest}
    >
        +{children}
    </ChakraBadge>
);

export default Badge;
