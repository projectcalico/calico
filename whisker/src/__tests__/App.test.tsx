import { render, screen } from '@/test-utils/helper';
import App from '../App';

jest.mock('@/pages', () => ({
    FlowLogsPage: () => 'Mock FlowLogsPage',
}));

jest.mock('@/hooks', () => ({
    useClusterId: jest.fn().mockReturnValue('fake-cluster-id'),
}));

describe('<App />', () => {
    it('should render the App component', () => {
        render(<App />);

        expect(screen.getByText('Calico Whisker')).toBeInTheDocument();
        expect(screen.getByText('Mock FlowLogsPage')).toBeInTheDocument();
    });
});
