import { act, render } from '@/test-utils/helper';
import StartTimeOmniFilter from '..';

const MockStartTimeFilter: any = {};

jest.mock(
    '../components/StartTimeFilter',
    () =>
        ({ onChange, onClear, onSubmit }: any) => {
            MockStartTimeFilter.onChange = onChange;
            MockStartTimeFilter.onClear = onClear;
            MockStartTimeFilter.onSubmit = onSubmit;
            return (
                <div data-testid='start-time-filter'>Mock StartTimeFilter</div>
            );
        },
);

describe('<StartTimeOmniFilter />', () => {
    const mockOnChange = jest.fn();
    const mockOnClear = jest.fn();

    const defaultProps = {
        selectedFilters: null,
        filterLabel: 'Start Time',
        filterId: 'startTime' as any,
        onChange: mockOnChange,
        onClear: mockOnClear,
        value: '5',
    };

    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should call onClear when StartTimeFilter calls onClear', () => {
        render(<StartTimeOmniFilter {...defaultProps} />);

        MockStartTimeFilter.onClear();

        expect(mockOnClear).toHaveBeenCalledTimes(1);
    });

    it('should call onChange with correct event when value changes', () => {
        render(<StartTimeOmniFilter {...defaultProps} />);

        // Simulate changing the start time to a different value
        act(() =>
            MockStartTimeFilter.onChange({
                label: '10 minutes ago',
                value: '10',
            }),
        );

        act(() => MockStartTimeFilter.onSubmit());

        expect(mockOnChange).toHaveBeenCalledWith({
            filterId: 'startTime',
            filterLabel: 'Start Time',
            filters: [{ label: '10 minutes ago', value: '10' }],
            operator: undefined,
        });
    });

    it('should not call onChange when value has not changed from initial', () => {
        render(<StartTimeOmniFilter {...defaultProps} />);

        // Simulate changing back to the initial value
        act(() =>
            MockStartTimeFilter.onChange({
                label: '5 minutes ago',
                value: '5',
            }),
        );
        act(() => MockStartTimeFilter.onSubmit());

        expect(mockOnChange).not.toHaveBeenCalled();
    });
});
