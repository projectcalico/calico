import { act, fireEvent, renderWithRouter, screen } from '@/test-utils/helper';
import { useLocation } from 'react-router-dom';
import TableFilters from '..';

jest.mock(
    '@/features/flowLogs/components/ListOmniFilter',
    () =>
        ({ filterId, filterLabel, selectedFilters }: any) => (
            <div data-testid={`list-filter-${filterId}`}>
                {filterLabel} selected=
                {selectedFilters
                    .map(({ label }: { label: string }) => label)
                    .join(',')}
            </div>
        ),
);

const PortOmniFilterMock = {
    onChange: jest.fn(),
};

jest.mock(
    '@/features/flowLogs/components/PortOmniFilter',
    () =>
        ({ filterLabel, onChange, port, protocol }: any) => {
            PortOmniFilterMock.onChange = onChange;
            return (
                <div>
                    {filterLabel} {port} {protocol}
                </div>
            );
        },
);

const PolicyOmniFilterMock = {
    onChange: jest.fn(),
    onClear: jest.fn(),
};
jest.mock(
    '@/features/flowLogs/components/PolicyOmniFilter',
    () =>
        ({ filterLabel, onChange, onClear }: any) => {
            PolicyOmniFilterMock.onChange = onChange;
            PolicyOmniFilterMock.onClear = onClear;
            return <div>{filterLabel} filter</div>;
        },
);

const ActionOmniFilterMock = {
    onChange: jest.fn(),
};
jest.mock(
    '@/features/flowLogs/components/ActionOmniFilter',
    () =>
        ({ onChange, value }: any) => {
            ActionOmniFilterMock.onChange = onChange;
            return (
                <div>
                    Mock ActionOmniFilter {value.action ?? 'no action'}{' '}
                    {value.staged_action ?? 'no staged action'}
                </div>
            );
        },
);

const StartTimeOmniFilterMock = {
    onChange: jest.fn(),
    onReset: jest.fn(),
};
jest.mock(
    '@/features/flowLogs/components/StartTimeOmniFilter',
    () =>
        ({ filterLabel, onChange, onReset, selectedFilters, value }: any) => {
            StartTimeOmniFilterMock.onChange = onChange;
            StartTimeOmniFilterMock.onReset = onReset;
            return (
                <div>
                    {filterLabel} value={value} selected=
                    {selectedFilters === null
                        ? 'none'
                        : selectedFilters.join(',')}
                </div>
            );
        },
);

const LocationProbe = () => (
    <div data-testid='location-search'>{useLocation().search}</div>
);

const renderOmniFilters = (route = '/') =>
    renderWithRouter(
        <>
            <TableFilters />
            <LocationProbe />
        </>,
        { routes: [route] },
    );

const currentParams = () =>
    new URLSearchParams(
        screen.getByTestId('location-search').textContent ?? '',
    );

describe('<TableFilters />', () => {
    it('should render a list filter chip with its selection from the URL', () => {
        renderOmniFilters('/?source_name=web&source_name=api');

        expect(screen.getByTestId('list-filter-source_name')).toHaveTextContent(
            'Source selected=web,api',
        );
    });

    it('should render every generic filter chip', () => {
        renderOmniFilters();

        for (const filterId of [
            'source_namespace',
            'source_name',
            'dest_namespace',
            'dest_name',
            'reporter',
        ]) {
            expect(
                screen.getByTestId(`list-filter-${filterId}`),
            ).toBeInTheDocument();
        }
    });

    it('should write the policy filter value to the URL', () => {
        renderOmniFilters();

        act(() => {
            PolicyOmniFilterMock.onChange('policy', 'my-policy');
        });

        expect(currentParams().getAll('policy')).toEqual(['my-policy']);
    });

    it('should remove the policy param when its value is empty', () => {
        renderOmniFilters('/?policy=%5B%5D');

        act(() => {
            PolicyOmniFilterMock.onChange('policy', '');
        });

        expect(currentParams().has('policy')).toBe(false);
    });

    it('should clear the policy filter', () => {
        renderOmniFilters('/?policy=%5B%5D');

        act(() => {
            PolicyOmniFilterMock.onClear();
        });

        expect(currentParams().has('policy')).toBe(false);
    });

    it('should write port and protocol to the URL together', () => {
        renderOmniFilters();

        act(() => {
            PortOmniFilterMock.onChange({ port: '8080', protocol: 'tcp' });
        });

        const params = currentParams();
        expect(params.getAll('dest_port')).toEqual(['8080']);
        expect(params.getAll('protocol')).toEqual(['tcp']);
    });

    it('should clear port and protocol when the port filter is emptied', () => {
        renderOmniFilters('/?dest_port=8080&protocol=tcp');

        act(() => {
            PortOmniFilterMock.onChange({ port: '', protocol: '' });
        });

        const params = currentParams();
        expect(params.has('dest_port')).toBe(false);
        expect(params.has('protocol')).toBe(false);
    });

    it('should pass selected port and protocol values to the port filter', () => {
        renderOmniFilters('/?dest_port=1234&protocol=tcp');

        expect(screen.getByText('Port 1234 tcp')).toBeInTheDocument();
    });

    it('should write action and staged action to the URL together', () => {
        renderOmniFilters();

        act(() => {
            ActionOmniFilterMock.onChange({
                action: 'Allow',
                staged_action: 'Deny',
            });
        });

        const params = currentParams();
        expect(params.getAll('action')).toEqual(['Allow']);
        expect(params.getAll('staged_action')).toEqual(['Deny']);
    });

    it('should clear action and staged action when emptied', () => {
        renderOmniFilters('/?action=Allow&staged_action=Deny');

        act(() => {
            ActionOmniFilterMock.onChange({ action: '', staged_action: '' });
        });

        const params = currentParams();
        expect(params.has('action')).toBe(false);
        expect(params.has('staged_action')).toBe(false);
    });

    it('should pass selected action values to the action filter', () => {
        renderOmniFilters('/?action=Allow&staged_action=Deny');

        expect(
            screen.getByText('Mock ActionOmniFilter Allow Deny'),
        ).toBeInTheDocument();
    });

    it('should show the reset button and clear all filters', () => {
        const policies = encodeURIComponent(
            JSON.stringify([{ name: 'allow-nginx', namespace: 'prod' }]),
        );
        renderOmniFilters(`/?policy=${policies}&source_name=web&ref=docs`);

        fireEvent.click(screen.getByTestId('omnifilterlist-reset'));

        const params = currentParams();
        expect(params.has('policy')).toBe(false);
        expect(params.has('source_name')).toBe(false);
        expect(params.get('ref')).toBe('docs');
    });

    it('should pass the selected start time to the start time filter', () => {
        renderOmniFilters('/?start_time=15');

        expect(
            screen.getByText('Start Time value=15 selected=15'),
        ).toBeInTheDocument();
    });

    it('should clear the start time filter on reset', () => {
        renderOmniFilters('/?start_time=15');

        act(() => {
            StartTimeOmniFilterMock.onReset();
        });

        expect(currentParams().has('start_time')).toBe(false);
    });

    it('should write the new start time to the URL', () => {
        renderOmniFilters();

        act(() => {
            StartTimeOmniFilterMock.onChange({
                filterId: 'start_time',
                filters: [{ label: '30', value: '30' }],
            });
        });

        expect(currentParams().getAll('start_time')).toEqual(['30']);
    });
});
