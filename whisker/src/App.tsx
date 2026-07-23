import { AppLayout, ChakraProvider } from '@/components';
import {
    AppErrorBoundary,
    FlowLogsErrorBoundary,
} from '@/components/core/ErrorBoundary';
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
import AppConfigProvider from '@/context/AppConfig';
import PromoBannerProvider from './context/PromoBanner';
import { useBuildInfo } from './hooks';

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

const Providers: React.FC<React.PropsWithChildren> = ({ children }) => (
    <AppConfigProvider>
        <PromoBannerProvider>{children}</PromoBannerProvider>
    </AppConfigProvider>
);

const App: React.FC = () => {
    useBuildInfo();

    return (
        <ChakraProvider>
            <QueryClientProvider client={queryClient}>
                <Providers>
                    <RouterProvider router={router} />
                </Providers>

                <ReactQueryDevtools initialIsOpen={false} />
            </QueryClientProvider>
        </ChakraProvider>
    );
};

export default App;
