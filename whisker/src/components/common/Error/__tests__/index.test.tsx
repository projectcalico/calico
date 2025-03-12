import { fireEvent, renderWithRouter, screen } from '@/test-utils/helper';
import { useNavigate } from 'react-router-dom';
import Error from '..';

jest.mock('react-router-dom', () => ({
    ...jest.requireActual('react-router-dom'),
    useNavigate: jest.fn(),
}));

describe('<Error />', () => {
    it('should click the button and navigate to the path', () => {
        const navigateMock = jest.fn();
        jest.mocked(useNavigate).mockReturnValue(navigateMock);
        const buttonLabel = 'Click me';
        const path = '/path';

        renderWithRouter(<Error buttonLabel={buttonLabel} navigateTo={path} />);

        fireEvent.click(screen.getByRole('button', { name: buttonLabel }));

        expect(navigateMock).toHaveBeenCalledWith(path);
    });
});
