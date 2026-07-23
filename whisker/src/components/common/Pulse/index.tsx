import { SkeletonCircle, SkeletonProps } from '@chakra-ui/react';

const Pulse: React.FC<SkeletonProps> = (props) => (
    <SkeletonCircle
        startColor='experimental-token-bg-brand'
        endColor='experimental-token-bg-empty'
        speed={1}
        {...props}
    />
);

export default Pulse;
