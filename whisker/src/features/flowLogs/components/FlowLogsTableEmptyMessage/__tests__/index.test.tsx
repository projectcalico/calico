import { render, screen } from '@/test-utils/helper';
import FlowLogsTableEmptyMessage from '..';

describe('FlowLogsTableEmptyMessage', () => {
    it('should render a generic message when there are no active filters', () => {
        render(<FlowLogsTableEmptyMessage hasActiveFilters={false} />);

        expect(screen.getByText('Nothing to see yet.')).toBeInTheDocument();
        expect(
            screen.getByText('Flows will start to appear shortly.'),
        ).toBeInTheDocument();
    });

    it('should render a filter-specific message when there are active filters', () => {
        render(<FlowLogsTableEmptyMessage hasActiveFilters={true} />);

        expect(screen.getByText('Nothing to see yet.')).toBeInTheDocument();
        expect(
            screen.getByText(
                'Waititing for flows that match the active filters.',
            ),
        ).toBeInTheDocument();
    });
});
