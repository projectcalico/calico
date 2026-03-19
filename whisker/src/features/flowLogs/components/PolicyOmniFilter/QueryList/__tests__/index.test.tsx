import { act, fireEvent, render, screen } from '@/test-utils/helper';
import QueryList, { QuerySelect } from '..';
import { getDefaultExpanded, updateQueryField } from '../../utils';

jest.mock('../../utils');
const mockedGetDefaultExpanded = jest.mocked(getDefaultExpanded);
const mockedUpdateQueryField = jest.mocked(updateQueryField);

const QuerySelectMock = { onChange: jest.fn() };
jest.mock('../../QuerySelect', () => {
    const component = ({ label, filterKey, value, onChange }: any) => {
        if (label === 'Kind') {
            QuerySelectMock.onChange = onChange;
        }
        return (
            <div
                data-testid={`query-select-${label.toLowerCase()}`}
                data-filter-key={filterKey}
                data-value={value?.value ?? ''}
            >
                {label}
            </div>
        );
    };
    component.displayName = 'QuerySelect';
    return { __esModule: true, default: component };
});

jest.mock('../../QueryLabel', () => {
    const component = ({ query }: any) => (
        <span data-testid='query-label'>{JSON.stringify(query)}</span>
    );
    component.displayName = 'QueryLabel';
    return { __esModule: true, default: component };
});

const defaultProps = {
    queries: [{}] as QuerySelect[],
    onChange: jest.fn(),
};

describe('<QueryList />', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        mockedGetDefaultExpanded.mockReturnValue('0');
    });

    it('renders a single empty query as an accordion item', () => {
        render(<QueryList {...defaultProps} />);

        expect(screen.getAllByTestId('accordion-item')).toHaveLength(1);
    });

    it('renders QuerySelect for each policy filter field', () => {
        render(<QueryList {...defaultProps} />);

        expect(screen.getByTestId('query-select-kind')).toBeInTheDocument();
        expect(screen.getByTestId('query-select-tier')).toBeInTheDocument();
        expect(
            screen.getByTestId('query-select-namespace'),
        ).toBeInTheDocument();
        expect(screen.getByTestId('query-select-name')).toBeInTheDocument();
    });

    it('renders multiple queries with "or" separator between them', () => {
        render(
            <QueryList
                {...defaultProps}
                queries={[
                    {
                        kind: {
                            label: 'NetworkPolicy',
                            value: 'NetworkPolicy',
                        },
                    },
                    {
                        kind: {
                            label: 'GlobalNetworkPolicy',
                            value: 'GlobalNetworkPolicy',
                        },
                    },
                ]}
            />,
        );

        expect(screen.getAllByTestId('accordion-item')).toHaveLength(2);
        expect(screen.getByText('or')).toBeInTheDocument();
    });

    it('does not render "or" separator after the last query', () => {
        render(
            <QueryList
                {...defaultProps}
                queries={[
                    {
                        kind: {
                            label: 'NetworkPolicy',
                            value: 'NetworkPolicy',
                        },
                    },
                ]}
            />,
        );

        expect(screen.queryByText('or')).not.toBeInTheDocument();
    });

    it('adds a new empty query when "Add Query" is clicked', () => {
        render(<QueryList {...defaultProps} />);

        fireEvent.click(screen.getByText('+ Add Query'));

        expect(defaultProps.onChange).toHaveBeenCalledWith([{}, {}]);
    });

    it('disables "Add Query" button when there are 5 queries', () => {
        render(<QueryList {...defaultProps} queries={[{}, {}, {}, {}, {}]} />);

        expect(screen.getByText('+ Add Query')).toBeDisabled();
    });

    it('does not disable "Add Query" button when there are fewer than 5 queries', () => {
        render(<QueryList {...defaultProps} queries={[{}, {}, {}]} />);

        expect(screen.getByText('+ Add Query')).not.toBeDisabled();
    });

    it('removes a query when the delete button is clicked', () => {
        const queries: QuerySelect[] = [
            { kind: { label: 'NetworkPolicy', value: 'NetworkPolicy' } },
            {
                kind: {
                    label: 'GlobalNetworkPolicy',
                    value: 'GlobalNetworkPolicy',
                },
            },
        ];
        render(<QueryList {...defaultProps} queries={queries} />);

        const deleteButtons = screen.getAllByLabelText('Delete query');
        fireEvent.click(deleteButtons[0]);

        expect(defaultProps.onChange).toHaveBeenCalledWith([queries[1]]);
    });

    it('passes query values to QuerySelect components', () => {
        const query: QuerySelect = {
            kind: { label: 'NetworkPolicy', value: 'NetworkPolicy' },
            tier: { label: 'default', value: 'default' },
        };
        render(<QueryList {...defaultProps} queries={[query]} />);

        expect(screen.getByTestId('query-select-kind')).toHaveAttribute(
            'data-value',
            'NetworkPolicy',
        );
        expect(screen.getByTestId('query-select-tier')).toHaveAttribute(
            'data-value',
            'default',
        );
    });

    it('delegates to updateQueryField when a field value changes', () => {
        const updatedQueries: QuerySelect[] = [
            { kind: { label: 'NetworkPolicy', value: 'NetworkPolicy' } },
        ];
        mockedUpdateQueryField.mockReturnValue(updatedQueries);

        render(<QueryList {...defaultProps} />);

        const newValue = { label: 'NetworkPolicy', value: 'NetworkPolicy' };
        act(() => {
            QuerySelectMock.onChange(newValue);
        });

        expect(mockedUpdateQueryField).toHaveBeenCalledWith(
            [{}],
            0,
            'kind',
            newValue,
        );
        expect(defaultProps.onChange).toHaveBeenCalledWith(updatedQueries);
    });

    it('calls getDefaultExpanded with queries on mount', () => {
        const queries: QuerySelect[] = [
            { kind: { label: 'NetworkPolicy', value: 'NetworkPolicy' } },
            {},
        ];
        render(<QueryList {...defaultProps} queries={queries} />);

        expect(mockedGetDefaultExpanded).toHaveBeenCalledWith(queries);
    });

    it('expands the accordion item returned by getDefaultExpanded', () => {
        mockedGetDefaultExpanded.mockReturnValue('1');

        render(
            <QueryList
                {...defaultProps}
                queries={[
                    {
                        kind: {
                            label: 'NetworkPolicy',
                            value: 'NetworkPolicy',
                        },
                    },
                    {},
                ]}
            />,
        );

        const items = screen.getAllByTestId('accordion-item');
        expect(items[0]).toHaveAttribute('data-state', 'closed');
        expect(items[1]).toHaveAttribute('data-state', 'open');
    });

    it('does not expand any accordion item when getDefaultExpanded returns empty string', () => {
        mockedGetDefaultExpanded.mockReturnValue('');

        render(
            <QueryList
                {...defaultProps}
                queries={[
                    {
                        kind: {
                            label: 'NetworkPolicy',
                            value: 'NetworkPolicy',
                        },
                    },
                    {
                        kind: {
                            label: 'GlobalNetworkPolicy',
                            value: 'GlobalNetworkPolicy',
                        },
                    },
                ]}
            />,
        );

        const items = screen.getAllByTestId('accordion-item');
        expect(items[0]).toHaveAttribute('data-state', 'closed');
        expect(items[1]).toHaveAttribute('data-state', 'closed');
    });
});
