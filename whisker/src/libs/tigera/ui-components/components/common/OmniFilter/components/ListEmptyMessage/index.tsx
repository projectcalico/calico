import { Flex, Text } from '@chakra-ui/react';

type ListEmptyMessageProps = {
    height?: number;
};

const ListEmptyMessage: React.FC<
    React.PropsWithChildren<ListEmptyMessageProps>
> = ({ height, children }) => (
    <Flex height={`${height}px`} alignItems='center'>
        <Text color='tigeraGrey.600' px={3}>
            {children}
        </Text>
    </Flex>
);

export default ListEmptyMessage;
