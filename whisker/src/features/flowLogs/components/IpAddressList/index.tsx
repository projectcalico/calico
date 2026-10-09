import React from 'react';
import { Flex, Text } from '@chakra-ui/react';

type IpAddressListProps = {
    ips: string[];
};

const IpAddressList: React.FC<IpAddressListProps> = ({ ips }) => (
    <Flex wrap='wrap' columnGap={4} data-testid='ip-address-list'>
        {ips.map((ip) => (
            <Text as='span' key={ip}>
                {ip}
            </Text>
        ))}
    </Flex>
);

export default IpAddressList;
