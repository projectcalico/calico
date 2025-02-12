import { fireEvent, render, screen } from '@/test-utils/helper';
import OmniFilter from '../index';
import OmniRangeList from '../components/OmniRangeList';

jest.mock('../../Select', () => ({ options = [], onChange, ...rest }: any) => {
    const handleChange = (event: any) => {
        const option = options.find(
            (option: { value: string }) =>
                option.value === event.currentTarget.value,
        );
        onChange(option);
    };
    return (
        <select data-testid='react-select' onChange={handleChange} {...rest}>
            {options.map(({ label, value }: any) => (
                <option key={value} value={value}>
                    {label}
                </option>
            ))}
        </select>
    );
});

const filterLabel = 'unit-test';
const filterId = 'unit-test';
const testId = 'data-test-id';
const filters = [
    { label: 'Filter 1', value: '1' },
    { label: 'Filter 2', value: '2' },
    { label: 'Filter 3', value: '3' },
];

describe('OmniFilter', () => {
    const openPopover = () =>
        fireEvent.click(screen.getByRole('button', { name: filterLabel }));

    const defaultProps = {
        filterId,
        filterLabel,
        filters,
        onChange: jest.fn(),
        onClear: jest.fn(),
        selectedFilters: [],
        seletedOperator: '',
        inMemorySearch: true,
        'data-testid': testId,
    };

    it('should render the option labels', () => {
        render(<OmniFilter {...defaultProps} />);

        expect(
            screen.getByTestId(`${testId}-button-chevron-icon`),
        ).toBeInTheDocument();

        openPopover();

        filters.forEach(({ label }) =>
            expect(screen.getByText(label)).toBeInTheDocument(),
        );
        expect(
            screen.getByTestId(`${testId}-operator-select`),
        ).toBeInTheDocument();

        expect(screen.queryByTestId(`omni-radio-list`)).not.toBeInTheDocument();
    });

    it('should not render the operator', () => {
        render(<OmniFilter {...defaultProps} showOperatorSelect={false} />);

        openPopover();

        expect(
            screen.queryByTestId(`${testId}-operator-select`),
        ).not.toBeInTheDocument();
    });

    it('should not render the search', () => {
        render(<OmniFilter {...defaultProps} showSearch={false} />);

        openPopover();

        expect(
            screen.queryByTestId(`${testId}-search-filter`),
        ).not.toBeInTheDocument();
    });

    it('should not render the operator on the button', () => {
        render(<OmniFilter {...defaultProps} showSelectedOnButton={false} />);

        openPopover();

        expect(
            screen.queryByTestId(`${testId}-button-text`),
        ).not.toBeInTheDocument();
    });

    it('should not render the button icon', () => {
        render(<OmniFilter {...defaultProps} showButtonIcon={false} />);

        expect(
            screen.queryByTestId(`${testId}-button-chevron-icon`),
        ).not.toBeInTheDocument();
    });

    it('should render a radio list', () => {
        render(<OmniFilter {...defaultProps} listType='radio' />);

        openPopover();

        expect(screen.queryByTestId(`omni-radio-list`)).toBeInTheDocument();
    });

    it('should render the selected option and operator in the button', () => {
        const operator = '!=';

        render(
            <OmniFilter
                {...defaultProps}
                selectedFilters={[filters[0], filters[1]]}
                selectedOperator={operator}
            />,
        );

        expect(
            screen.getByTestId(`${testId}-button-trigger`),
        ).toHaveTextContent(`${filterLabel} ${operator} ${filters[0].label}+1`);
    });

    it('should call onChange when the operator is changed', () => {
        const onChange = jest.fn();

        render(<OmniFilter {...defaultProps} onChange={onChange} />);

        openPopover();

        fireEvent.change(screen.getByTestId(`${testId}-operator-select`), {
            target: { value: '=' },
        });

        expect(onChange).toHaveBeenCalledWith({
            operator: '=',
            filters: [],
            filterLabel,
            filterId,
        });
    });

    it('should call onChange when the a filter is changed', () => {
        const [filter] = filters;
        const onChange = jest.fn();

        render(<OmniFilter {...defaultProps} onChange={onChange} />);

        openPopover();

        fireEvent.click(screen.getByText(filter.label));

        expect(onChange).toHaveBeenCalledWith({
            operator: '=',
            filters: [filter],
            filterLabel,
            filterId,
        });
    });

    it('should filter the data with the search input for in memory search', () => {
        const { rerender } = render(<OmniFilter {...defaultProps} />);

        openPopover();

        fireEvent.change(screen.getByTestId(`${testId}-search-filter`), {
            target: { value: filters[2].label },
        });

        expect(screen.getByText(filters[2].label)).toBeInTheDocument();
        expect(screen.queryByText(filters[1].label)).not.toBeInTheDocument();
        expect(screen.queryByText(filters[0].label)).not.toBeInTheDocument();

        // update filter when search is taking place should result in list not being updated
        rerender(
            <OmniFilter
                {...defaultProps}
                filters={[...filters, { label: 'filter4', value: 'filter4' }]}
            />,
        );
        expect(screen.queryByText('filter4')).not.toBeInTheDocument();
    });

    it('should filter the data with the request events when inMemorySearch=false', () => {
        const mockOnRequestSearch = jest.fn();
        const mockOnRequestMore = jest.fn();
        const { rerender } = render(
            <OmniFilter
                {...defaultProps}
                inMemorySearch={false}
                totalItems={200}
                onRequestSearch={mockOnRequestSearch}
                onRequestMore={mockOnRequestMore}
            />,
        );

        openPopover();

        expect(
            screen.getByTestId(`${testId}-search-filter`),
        ).toBeInTheDocument();

        fireEvent.change(screen.getByTestId(`${testId}-search-filter`), {
            target: { value: 'mock search text' },
        });

        fireEvent.click(screen.getByTestId('show-more-button'));
        expect(mockOnRequestMore).toHaveBeenCalledWith(
            'unit-test',
            'mock search text',
        );
        expect(mockOnRequestSearch).toHaveBeenCalledWith(
            'unit-test',
            'mock search text',
        );

        // update filter when search is taking place should result in list being updated for inMemorySearch=false (to cater for pagination etc)
        rerender(
            <OmniFilter
                {...defaultProps}
                filters={[...filters, { label: 'filter4', value: 'filter4' }]}
                inMemorySearch={false}
                totalItems={200}
                onRequestSearch={mockOnRequestSearch}
                onRequestMore={mockOnRequestMore}
            />,
        );
        expect(screen.queryByText('filter4')).toBeInTheDocument();
    });

    it('should call onClear', () => {
        const onClear = jest.fn();

        render(
            <OmniFilter
                {...defaultProps}
                onClear={onClear}
                selectedFilters={[filters[0]]}
            />,
        );

        fireEvent.click(
            screen.getByRole('button', {
                name: `${filterLabel} = ${filters[0].label}`,
            }),
        );

        fireEvent.click(screen.getByText('Clear selection'));

        expect(onClear).toHaveBeenCalled();
    });

    it('should show a loading skeleton', () => {
        render(<OmniFilter {...defaultProps} isLoading={true} />);

        openPopover();

        expect(
            screen.getByTestId(`${testId}-list-skeleton`),
        ).toBeInTheDocument();
    });

    it('should customize an omnifilter with an OmniRangeList', () => {
        render(
            <OmniFilter
                {...defaultProps}
                internalListComponent={OmniRangeList}
                filters={[
                    { label: 'Custom gte label', value: 'gte' },
                    { label: 'Custom lte label', value: 'lte' },
                ]}
            />,
        );

        openPopover();

        expect(screen.getByTestId('omni-range-list')).toBeInTheDocument();
    });

    it('should render a custom description', () => {
        const data = { desc: 'Some random description' };
        const filters = [
            {
                label: 'Filter 1',
                value: '1',
                data: { desc: 'Some random description' },
            },
        ];
        render(
            <OmniFilter
                {...defaultProps}
                listType='checkbox'
                filters={filters}
                internalListComponentProps={{
                    listItemHeight: 50,
                    DescriptionComponent: ({ data }: any) => <>{data.desc}</>,
                }}
            />,
        );

        openPopover();

        expect(screen.getByText(filters[0].label)).toBeInTheDocument();
        expect(screen.getByText(data.desc)).toBeInTheDocument();
    });

    it('should render selected list when showSelectedList is provided ', () => {
        const { rerender } = render(
            <OmniFilter
                {...defaultProps}
                filters={filters}
                showSelectedList={true}
                labelSelectedListHeader='mock selected list'
            />,
        );

        openPopover();

        expect(
            screen.queryByText('mock selected list'),
        ).not.toBeInTheDocument();

        // update with selected filters
        rerender(
            <OmniFilter
                {...defaultProps}
                selectedFilters={[filters[0], filters[1]]}
                filters={filters}
                showSelectedList={true}
                labelSelectedListHeader='mock selected list'
            />,
        );

        expect(screen.getByText('mock selected list')).toBeInTheDocument();
    });
});
