import { CalicoCatIcon, CalicoWhiskerIcon } from '@/icons';
import { Flex, Heading, LinkBox, LinkOverlay, Text } from '@chakra-ui/react';
import React from 'react';
import { appHeaderStyles } from './styles';

const AppHeader: React.FC = () => {
    return (
        <Flex as='header' sx={appHeaderStyles}>
            <Flex alignItems='center'>
                <CalicoWhiskerIcon fontSize='xl' />
                <Heading fontSize='2xl'>Calico Whisker</Heading>
            </Flex>

            <LinkBox>
                <Flex alignItems='center' gap={2}>
                    <Flex alignItems='flex-end' flexDirection='column' gap={0}>
                        <Text fontSize='xs' as='span' fontWeight='medium'>
                            Calico Whisker is a simplified version of the
                        </Text>
                        <LinkOverlay
                            fontSize='xs'
                            fontWeight='bold'
                            color='tigeraGoldMedium'
                            isExternal
                            href='https://calicocloud.io'
                        >
                            Service Graph from Calico Cloud
                        </LinkOverlay>
                    </Flex>

                    <CalicoCatIcon fontSize='35px' />
                </Flex>
            </LinkBox>
        </Flex>
    );
};

export default AppHeader;
