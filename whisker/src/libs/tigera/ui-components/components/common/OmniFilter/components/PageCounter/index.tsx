import { totalItemsLabelStyles } from './styles';
import { Text } from '@chakra-ui/react';

const PageCounter: React.FC<React.PropsWithChildren> = ({ children }) => (
    <Text sx={totalItemsLabelStyles}>{children}</Text>
);

export default PageCounter;
