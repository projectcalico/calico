import { render, screen } from '@/test-utils/helper';
import App, { routes } from '../App';

jest.mock('@/pages', () => ({
    FlowLogsPage: () => 'Mock FlowLogsPage',
}));

jest.mock('@/hooks', () => ({
    ...jest.requireActual('@/hooks'),
    useClusterId: jest.fn().mockReturnValue('fake-cluster-id'),
}));

describe('<App />', () => {
    it('should render the App component', () => {
        render(<App />);

        expect(screen.getByText('Calico Whisker')).toBeInTheDocument();
        expect(screen.getByText('Mock FlowLogsPage')).toBeInTheDocument();
    });

    it('should define the flow logs route and a catch-all redirect', () => {
        expect(routes).toHaveLength(1);
        expect(routes[0].children).toEqual([
            expect.objectContaining({ path: 'flow-logs' }),
            expect.objectContaining({ path: '*' }),
        ]);
    });
});
