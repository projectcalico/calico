import { Badge as ChakraBadge } from '@chakra-ui/react';

const Badge: React.FC<React.PropsWithChildren> = ({ children }) => (
    <ChakraBadge variant='rounded' ml={1}>
        +{children}
    </ChakraBadge>
);

export default Badge;
