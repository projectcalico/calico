import { render, screen } from '@/test-utils/helper';
import AppConfigProvider from '..';
import { useAppConfigQuery } from '@/api';
import { useClusterId } from '@/hooks';

jest.mock('@/api', () => ({ useAppConfigQuery: jest.fn() }));

const TestComponent = () => {
    const clusterId = useClusterId();

    return <div>ClusterId = {clusterId}</div>;
};

describe('<AppConfig />', () => {
    it('should pass context to children', () => {
        const clusterId = 'my-cluster-id';
        jest.mocked(useAppConfigQuery).mockReturnValue({
            data: undefined,
        } as any);

        const { rerender } = render(
            <AppConfigProvider>
                <TestComponent />
            </AppConfigProvider>,
        );

        expect(screen.getByText(/ClusterId =/));

        jest.mocked(useAppConfigQuery).mockReturnValue({
            data: {
                config: {
                    cluster_id: clusterId,
                    cluster_type: '',
                    calico_version: '',
                    notifications: '',
                },
            },
        } as any);

        rerender(
            <AppConfigProvider>
                <TestComponent />
            </AppConfigProvider>,
        );

        expect(screen.getByText(`ClusterId = ${clusterId}`));
    });
});
