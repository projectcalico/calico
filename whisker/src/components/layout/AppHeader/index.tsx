import { CalicoCatIcon, CalicoWhiskerIcon } from '@/icons';
import { Flex, Heading, LinkBox, LinkOverlay, Text } from '@chakra-ui/react';
import React from 'react';
import { appHeaderStyles } from './styles';
import { useClusterId } from '@/hooks';

const AppHeader: React.FC = () => {
    const clusterId = useClusterId();

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
                            data-testId='app-header-calico-cloud-link'
                            fontSize='xs'
                            fontWeight='bold'
                            color='tigeraGoldMedium'
                            isExternal
                            href={`https://calicocloud.io?utm_source=whisker&utm_medium=header-link&utm_campaign=oss-ui&whisker-id=${clusterId}`}
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
