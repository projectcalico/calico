import { WarningTwoIcon } from '@chakra-ui/icons';
import { Button, Center, SystemStyleObject, Text } from '@chakra-ui/react';
import { To, useNavigate } from 'react-router-dom';

type ErrorProps = {
    buttonLabel: string;
    navigateTo: To | number;
    sx?: SystemStyleObject;
};

const Error: React.FC<ErrorProps> = ({ buttonLabel, navigateTo, sx }) => {
    const navigate = useNavigate();

    return (
        <Center flexDirection='column' height='100%' gap={12} sx={sx}>
            <Center flexDirection='column' gap={4}>
                <WarningTwoIcon color='tigeraGoldMedium40' boxSize={24} />

                <Text fontSize='xl' fontWeight='bold'>
                    Ooops, something went wrong.
                </Text>

                <Text fontSize='md'>An unexpected error occurred.</Text>
            </Center>
            <Button
                onClick={() => navigate(navigateTo as To)}
                fontSize='lg'
                size='lg'
            >
                {buttonLabel}
            </Button>
        </Center>
    );
};

export default Error;
