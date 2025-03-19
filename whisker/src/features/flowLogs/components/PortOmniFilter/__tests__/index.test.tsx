import { render, screen, waitFor } from '@/test-utils/helper';
import { CustomOmniFilterParam } from '@/utils/omniFilter';
import userEvent from '@testing-library/user-event';
import PortOmniFilter from '..';

const MockSelect = {
    onChange: jest.fn(),
};
jest.mock(
    '@/libs/tigera/ui-components/components/common/Select',
    () =>
        ({ onChange }: any) => {
            MockSelect.onChange = onChange;
            return <div>Select</div>;
        },
);

const defaultProps = {
    port: '',
    protocol: '',
    selectedFilters: null,
    filterLabel: '',
    filterId: CustomOmniFilterParam.port,
    onChange: jest.fn(),
};

describe('<PortOmniFilter />', () => {
    const openFilter = async () => {
        userEvent.click(screen.getByRole('button', { name: 'Port' }));
        await screen.findByTestId('port-filter-popover-body');
    };

    const typePort = async (port: string) => {
        const input = screen.getByLabelText('Port');
        await userEvent.type(input, port);
        MockSelect.onChange({ value: 'tcp' });
    };

    it('should submit the filter values', async () => {
        const port = '8081';
        const mockOnChange = jest.fn();
        render(<PortOmniFilter {...defaultProps} onChange={mockOnChange} />);

        await openFilter();

        await typePort(port);

        userEvent.click(screen.getByRole('button', { name: 'Apply filter' }));

        await waitFor(() => {
            expect(mockOnChange).toHaveBeenCalledWith({
                port: String(port),
                protocol: 'tcp',
            });
        });
    });

    it('should clear the filter', async () => {
        const port = '8081';
        const mockOnChange = jest.fn();
        render(<PortOmniFilter {...defaultProps} onChange={mockOnChange} />);

        await openFilter();

        await typePort(port);

        userEvent.click(screen.getByRole('button', { name: 'Clear filter' }));

        await waitFor(() => {
            expect(mockOnChange).toHaveBeenCalledWith({
                port: null,
                protocol: null,
            });
        });
    });

    it('should clear the filter values', async () => {
        const port = '8081';
        const mockOnChange = jest.fn();
        render(<PortOmniFilter {...defaultProps} onChange={mockOnChange} />);

        await openFilter();

        await typePort(port);

        userEvent.click(screen.getByRole('button', { name: 'Clear filter' }));

        await waitFor(() => {
            expect(mockOnChange).toHaveBeenCalledWith({
                port: null,
                protocol: null,
            });
        });
    });

    it('should update values on props change', () => {
        const { rerender } = render(<PortOmniFilter {...defaultProps} />);

        screen.getByRole('button', { name: 'Port' });

        rerender(
            <PortOmniFilter {...defaultProps} port='2020' protocol='udp' />,
        );

        screen.getByRole('button', { name: 'Port = UDP:2020' });
    });
});
