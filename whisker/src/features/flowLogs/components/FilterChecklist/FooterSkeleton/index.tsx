import { Flex, Skeleton, useColorModeValue } from '@chakra-ui/react';

const FooterSkeleton = () => {
    const startColor = useColorModeValue('tigeraGrey.50', 'tigeraGrey.1000');
    const endColor = useColorModeValue('tigeraGrey.400', 'tigeraGrey.600');

    return (
        <Flex
            justifyContent='space-between'
            data-testid='checklist-footer-skeleton'
        >
            <Skeleton
                height='12px'
                width='45px'
                startColor={startColor}
                endColor={endColor}
                speed={0.9}
            />
            <Skeleton
                height='12px'
                width='60px'
                startColor={startColor}
                endColor={endColor}
                speed={0.9}
            />
        </Flex>
    );
};

export default FooterSkeleton;
