import { ChakraProvider } from '@chakra-ui/react';
import {
    createBrowserRouter,
    Navigate,
    RouteObject,
    RouterProvider,
} from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AppLayout } from '@/components';
import { FlowLogsPage } from '@/pages';
import { theme } from '@/theme';
import { FlowLogsContainer } from '@/features/flowLogs/components';

const queryClient = new QueryClient();

export const routes: RouteObject[] = [
    {
        element: <AppLayout />,
        children: [
            {
                path: 'flow-logs',
                element: <FlowLogsPage />,
                children: [
                    {
                        path: '',
                        element: <FlowLogsContainer />,
                    },
                    {
                        path: 'denied-flows',
                        element: <FlowLogsContainer />,
                    },
                ],
            },
            {
                path: '*',
                element: <Navigate to='flow-logs' />,
            },
        ],
    },
];

const router = createBrowserRouter(routes);

const App: React.FC = () => {
    return (
        <ChakraProvider theme={theme}>
            <QueryClientProvider client={queryClient}>
                <RouterProvider router={router} />
            </QueryClientProvider>
        </ChakraProvider>
    );
};

export default App;
