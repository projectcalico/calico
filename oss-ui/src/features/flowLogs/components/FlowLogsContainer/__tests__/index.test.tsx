import { render } from '@/test-utils/helper';
import FlowLogsContainer from '..';
import { useOutletContext } from 'react-router-dom';
import { useFlowLogs } from '../../../api';

jest.mock('react-router-dom', () => ({
    useOutletContext: jest.fn(),
}));

jest.mock('../../../api', () => ({
    useFlowLogs: jest.fn().mockReturnValue({}),
}));

describe('FlowLogsContainer', () => {
    it('should call useFlowLogs with denied query params', () => {
        jest.mocked(useOutletContext).mockReturnValue({ view: 'denied' });

        render(<FlowLogsContainer />);

        expect(useFlowLogs).toHaveBeenCalledWith({ action: 'deny' });
    });

    it('should call useFlowLogs with no query params', () => {
        jest.mocked(useOutletContext).mockReturnValue({ view: 'all' });

        render(<FlowLogsContainer />);

        expect(useFlowLogs).toHaveBeenCalledWith(undefined);
    });
});
