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
                <CalicoWhiskerIcon fontSize='24px' />
                <Heading fontSize='2xl'>Calico Whisker</Heading>
            </Flex>

            <LinkBox>
                <Flex alignItems='center' gap={2}>
                    <Flex alignItems='flex-end' flexDirection='column' gap={0}>
                        <Text fontSize='sm' as='span' fontWeight='medium'>
                            Calico Whisker is a simplified version of the
                        </Text>
                        <LinkOverlay
                            data-testId='app-header-calico-cloud-link'
                            fontSize='sm'
                            fontWeight='bold'
                            color='tigeraGoldMedium'
                            isExternal
                            href={`https://calicocloud.io?utm_source=whisker&utm_medium=header-link&utm_campaign=oss-ui&whisker_id=${clusterId}`}
                        >
                            <Text>Service Graph from Calico Cloud</Text>
                        </LinkOverlay>
                    </Flex>

                    <CalicoCatIcon fontSize='40px' />
                </Flex>
            </LinkBox>
        </Flex>
    );
};

export default AppHeader;
