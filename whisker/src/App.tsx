import {
    createBrowserRouter,
    Navigate,
    RouteObject,
    RouterProvider,
} from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AppLayout, ChakraProvider } from '@/components';
import { FlowLogsPage } from '@/pages';
import { FlowLogsContainer } from '@/features/flowLogs/components';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';
import React from 'react';

const queryClient = new QueryClient({
    defaultOptions: {
        queries: {
            refetchOnWindowFocus: false,
            refetchOnMount: false,
            retry: 1,
        },
    },
});

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
                    // {
                    //     path: 'denied-flows',
                    //     element: <FlowLogsContainer />,
                    // },
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
        <ChakraProvider>
            <QueryClientProvider client={queryClient}>
                <RouterProvider router={router} />
                <ReactQueryDevtools initialIsOpen={false} />
            </QueryClientProvider>
        </ChakraProvider>
    );
};

export default App;
