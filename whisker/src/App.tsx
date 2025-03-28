import { AppLayout, ChakraProvider } from '@/components';
import { FlowLogsContainer } from '@/features/flowLogs/components';
import { FlowLogsPage } from '@/pages';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';
import React from 'react';
import {
    Navigate,
    RouteObject,
    RouterProvider,
    createBrowserRouter,
} from 'react-router-dom';
import {
    AppErrorBoundary,
    FlowLogsErrorBoundary,
} from '@/components/core/ErrorBoundary';

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
                    {
                        path: 'denied-flows',
                        element: <FlowLogsContainer />,
                    },
                ],
                ErrorBoundary: FlowLogsErrorBoundary,
            },
            {
                path: '*',
                element: <Navigate to='flow-logs' />,
            },
        ],
        ErrorBoundary: AppErrorBoundary,
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
