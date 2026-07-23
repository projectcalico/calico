import { fireEvent, render, screen } from '@/test-utils/helper';
import OmniSelectList from '..';

jest.mock('react-window', () => ({
    FixedSizeList: ({ children: Row, itemCount }: any) => (
        <ul>
            {Array.from({ length: itemCount }, (_, i) => (
                <li key={i}>{Row({ index: i, style: {} })}</li>
            ))}
        </ul>
    ),
}));

const options = [
    { label: 'NetworkPolicy', value: 'NetworkPolicy' },
    { label: 'GlobalNetworkPolicy', value: 'GlobalNetworkPolicy' },
];

const defaultProps = {
    filteredSelectedOptions: [],
    showMoreButton: false,
    isLoadingMore: false,
    options,
    selectedOptions: [] as any[],
    onChange: jest.fn(),
    emptyMessage: 'No results',
};

describe('<OmniSelectList />', () => {
    beforeEach(() => jest.clearAllMocks());

    it('renders the empty message when there are no options', () => {
        render(<OmniSelectList {...defaultProps} options={[]} />);

        expect(screen.getByText('No results')).toBeInTheDocument();
    });

    it('calls onChange with the option when selecting an unselected item', () => {
        render(<OmniSelectList {...defaultProps} />);

        fireEvent.click(screen.getByText('NetworkPolicy'));

        expect(defaultProps.onChange).toHaveBeenCalledWith([options[0]]);
    });

    it('calls onChange with an empty array when deselecting a selected item', () => {
        render(
            <OmniSelectList {...defaultProps} selectedOptions={[options[0]]} />,
        );

        fireEvent.click(screen.getByText('NetworkPolicy'));

        expect(defaultProps.onChange).toHaveBeenCalledWith([]);
    });
});
