import { Badge as ChakraBadge, BadgeProps } from '@chakra-ui/react';

type Props = {
    showPlus?: boolean;
};
const Badge: React.FC<React.PropsWithChildren & BadgeProps & Props> = ({
    children,
    showPlus = true,
    ...rest
}) => (
    <ChakraBadge
        ml={1}
        variant='solid'
        color='tigeraLightBlue'
        fontSize='sm'
        {...rest}
    >
        {showPlus && '+'}
        {children}
    </ChakraBadge>
);

export default Badge;
