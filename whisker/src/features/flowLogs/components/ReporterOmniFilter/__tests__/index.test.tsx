import { useInfiniteFilterQuery } from '@/features/flowLogs/api';
import { fireEvent, renderWithRouter, screen } from '@/test-utils/helper';
import { OmniFilterOption } from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import { useLocation } from 'react-router-dom';
import ReporterOmniFilter from '..';

jest.mock('@/features/flowLogs/api', () => ({
    useInfiniteFilterQuery: jest.fn(),
}));

const omniFilterProps: Record<string, any> = {};

jest.mock(
    '@/libs/tigera/ui-components/components/common/OmniFilter',
    () => (props: any) => {
        Object.assign(omniFilterProps, props);

        return (
            <div data-testid='omni-filter'>
                <div>{props.filterLabel}</div>
                <div data-testid='selected-label'>
                    {props.formatSelectedLabel(props.selectedFilters)}
                </div>
                <ul>
                    {props.filters.map(({ label, value }: OmniFilterOption) => (
                        <li key={value}>{label}</li>
                    ))}
                </ul>
                <button
                    onClick={() =>
                        props.onChange({
                            filterId: props.filterId,
                            filterLabel: props.filterLabel,
                            operator: undefined,
                            filters: [{ label: 'Destination', value: 'Dst' }],
                        })
                    }
                >
                    on change
                </button>
                <span onClick={props.onClear}>on clear</span>
                <button onClick={props.onReady}>on ready</button>
            </div>
        );
    },
);

const LocationProbe = () => (
    <div data-testid='location-search'>{useLocation().search}</div>
);

const renderReporterOmniFilter = (
    route = '/',
    selectedFilters: OmniFilterOption[] = [],
) =>
    renderWithRouter(
        <>
            <ReporterOmniFilter
                filterId='reporter'
                filterLabel='Reporter'
                selectedFilters={selectedFilters}
            />
            <LocationProbe />
        </>,
        { routes: [route] },
    );

const currentSearch = () => screen.getByTestId('location-search').textContent;

describe('<ReporterOmniFilter />', () => {
    beforeEach(() => {
        jest.mocked(useInfiniteFilterQuery).mockClear();
    });

    it('should offer exactly the Source and Destination options', () => {
        renderReporterOmniFilter();

        expect(screen.getByText('Source')).toBeInTheDocument();
        expect(screen.getByText('Destination')).toBeInTheDocument();
    });

    it('should render as a radio list without a search box', () => {
        renderReporterOmniFilter();

        expect(omniFilterProps.listType).toBe('radio');
        expect(omniFilterProps.showSearch).toBe(false);
    });

    it('should never request hint data', () => {
        renderReporterOmniFilter();

        fireEvent.click(screen.getByText('on ready'));

        expect(useInfiniteFilterQuery).not.toHaveBeenCalled();
    });

    it.each([
        ['Src', 'Source'],
        ['Dst', 'Destination'],
    ])(
        'should render the selected value %s as the label %s',
        (value, label) => {
            renderReporterOmniFilter('/', [{ label, value }]);

            expect(screen.getByTestId('selected-label')).toHaveTextContent(
                label,
            );
        },
    );

    it('should render an empty selection as an empty label', () => {
        renderReporterOmniFilter();

        expect(screen.getByTestId('selected-label')).toBeEmptyDOMElement();
    });

    it('should write the selected reporter to the URL', () => {
        renderReporterOmniFilter();

        fireEvent.click(screen.getByText('on change'));

        expect(currentSearch()).toBe('?reporter=Dst');
    });

    it('should clear the reporter param', () => {
        renderReporterOmniFilter('/?reporter=Src');

        fireEvent.click(screen.getByText('on clear'));

        expect(currentSearch()).toBe('');
    });
});
