import { fireEvent, renderWithRouter, screen } from '@/test-utils/helper';
import { useNavigate } from 'react-router-dom';
import { FlowLogsErrorBoundary, AppErrorBoundary } from '..';

jest.mock('react-router-dom', () => ({
    ...jest.requireActual('react-router-dom'),
    useNavigate: jest.fn(),
}));

describe('<FlowLogsErrorBoundary />', () => {
    it('should click the button and navigate to the path', () => {
        const navigateMock = jest.fn();
        jest.mocked(useNavigate).mockReturnValue(navigateMock);

        renderWithRouter(<FlowLogsErrorBoundary />);

        fireEvent.click(screen.getByRole('button', { name: 'Take me back' }));

        expect(navigateMock).toHaveBeenCalledWith('/flow-logs');
    });
});

describe('<AppErrorBoundary />', () => {
    it('should click the button and navigate to the path', () => {
        const navigateMock = jest.fn();
        jest.mocked(useNavigate).mockReturnValue(navigateMock);

        renderWithRouter(<AppErrorBoundary />);

        fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));

        expect(navigateMock).toHaveBeenCalledWith(0);
    });
});
