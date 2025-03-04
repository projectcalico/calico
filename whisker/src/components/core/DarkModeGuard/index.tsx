import { useColorMode } from '@chakra-ui/react';
import React from 'react';

const DarkModeGuard: React.FC<React.PropsWithChildren> = ({ children }) => {
    const colorMode = useColorMode();

    React.useEffect(() => {
        colorMode.setColorMode('dark');
    }, []);

    return <>{children}</>;
};

export default DarkModeGuard;
