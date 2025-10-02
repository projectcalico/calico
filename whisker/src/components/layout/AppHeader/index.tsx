import { CalicoCatIcon, CalicoWhiskerIcon } from '@/icons';
import { Flex, Heading, LinkBox, LinkOverlay, Text } from '@chakra-ui/react';
import React, { useEffect, useState } from 'react';
import { appHeaderStyles } from './styles';
import { useClusterId } from '@/hooks';

const AppHeader: React.FC = () => {
    const clusterId = useClusterId();
    const [stars, setStars] = useState<number | null>(null);
    const projectURL = "https://api.github.com/repos/projectcalico/calico";
    useEffect(() => {
        async function fetchStars() {
            try {
                const res = await fetch(projectURL);
                console.log(res.ok);
                if (!res.ok){
                     throw new Error(`GitHub API returned status ${res.status}`);
                }
                const data = await res.json();
                setStars(data.stargazers_count);
            } catch (err) {
                console.error('Failed to fetch stars', err);
            }
        }
        fetchStars();
    }, []);

    return (
        <Flex as='header' sx={appHeaderStyles}>
            <Flex alignItems='center'  gap={1}>
                <CalicoWhiskerIcon fontSize='24px' />
                <Heading fontSize='2xl'>Calico Whisker</Heading>
                <LinkBox>
                    <Flex alignItems='flex-start' gap={2}>
                        <LinkOverlay
                            isExternal
                            href={projectURL}
                        >
                            <Text fontSize='md' fontWeight='bold'>
                                {stars !== null ? "⭐ " + stars : '❤️ Calico? Give us a ⭐'} 
                            </Text>
                        </LinkOverlay>
                    </Flex>
                </LinkBox>
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

                    <CalicoCatIcon fontSize='42px' />
                </Flex>
            </LinkBox>
        </Flex>
    );
};

export default AppHeader;
