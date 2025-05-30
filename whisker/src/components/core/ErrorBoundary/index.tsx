import Error from '../../common/Error';

export const FlowLogsErrorBoundary = () => (
    <Error buttonLabel='Take me back' navigateTo='/flow-logs' />
);

export const AppErrorBoundary = () => (
    <Error buttonLabel='Refresh' navigateTo={0} sx={{ height: '100vh' }} />
);
