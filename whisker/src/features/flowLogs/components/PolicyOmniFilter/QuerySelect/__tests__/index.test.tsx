import { render, screen } from '@/test-utils/helper';
import QuerySelect from '..';

jest.mock('../../PolicySelect', () => {
    const component = (props: any) => (
        <div
            data-testid='policy-select'
            data-filter-key={props.filterKey}
            data-value={props.value?.value ?? ''}
            data-show-search={props.showSearch}
        />
    );
    component.displayName = 'PolicySelect';
    return { __esModule: true, default: component };
});

describe('<QuerySelect />', () => {
    it('renders the label and passes all props to PolicySelect', () => {
        const value = { label: 'NetworkPolicy', value: 'NetworkPolicy' };
        const onChange = jest.fn();

        render(
            <QuerySelect
                label='Kind'
                filterKey={'policyKind'}
                value={value}
                onChange={onChange}
                showSearch={false}
                placeholder='Select a kind...'
            />,
        );

        expect(screen.getByText('Kind')).toBeInTheDocument();

        const select = screen.getByTestId('policy-select');
        expect(select).toHaveAttribute('data-filter-key', 'policyKind');
        expect(select).toHaveAttribute('data-value', 'NetworkPolicy');
        expect(select).toHaveAttribute('data-show-search', 'false');
    });

    it('defaults showSearch to true when not provided', () => {
        render(
            <QuerySelect
                label='Kind'
                filterKey={'policyKind'}
                value={null}
                onChange={jest.fn()}
                placeholder='Select a kind...'
            />,
        );

        expect(screen.getByTestId('policy-select')).toHaveAttribute(
            'data-show-search',
            'true',
        );
    });
});
