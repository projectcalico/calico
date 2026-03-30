import { render, screen } from '@/test-utils/helper';
import { FilterKey } from '@/utils/omniFilter';
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
                filterKey={FilterKey.policyKind}
                value={value}
                onChange={onChange}
                showSearch={false}
            />,
        );

        expect(screen.getByText('Kind')).toBeInTheDocument();

        const select = screen.getByTestId('policy-select');
        expect(select).toHaveAttribute('data-filter-key', FilterKey.policyKind);
        expect(select).toHaveAttribute('data-value', 'NetworkPolicy');
        expect(select).toHaveAttribute('data-show-search', 'false');
    });
});
