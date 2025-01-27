import { render, screen } from '@/test-utils/helper';
import App from '../App';

jest.mock('@/pages', () => ({
    FlowLogsPage: () => 'Mock FlowLogsPage',
}));

describe('<App />', () => {
    it('should render the App component', () => {
        render(<App />);

        expect(screen.getByText('Calico Whisker')).toBeInTheDocument();
        expect(screen.getByText('Mock FlowLogsPage')).toBeInTheDocument();
    });
});
