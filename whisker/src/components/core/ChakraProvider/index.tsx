import React from 'react';
import { ChakraProvider as ChakraThemeProvider } from '@chakra-ui/react';
import { theme } from '@/theme';
import DarkModeGuard from '../DarkModeGuard';

const ChakraProvider: React.FC<React.PropsWithChildren> = ({ children }) => {
    return (
        <ChakraThemeProvider theme={theme}>
            <DarkModeGuard>{children}</DarkModeGuard>
        </ChakraThemeProvider>
    );
};

export default ChakraProvider;
