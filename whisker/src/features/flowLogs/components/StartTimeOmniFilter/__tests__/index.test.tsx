import { act, render } from '@/test-utils/helper';
import StartTimeOmniFilter from '..';

const MockStartTimeFilter: any = {};

jest.mock(
    '../components/StartTimeFilter',
    () =>
        ({ onChange, onClear, onClick }: any) => {
            MockStartTimeFilter.onChange = onChange;
            MockStartTimeFilter.onClear = onClear;
            MockStartTimeFilter.onClick = onClick;
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
        onReset: jest.fn(),
    };

    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should call onChange with correct event when value changes', () => {
        render(<StartTimeOmniFilter {...defaultProps} />);

        // Simulate changing the start time to a different value
        act(() =>
            MockStartTimeFilter.onChange({
                label: 'Last 10 minutes',
                value: '10',
            }),
        );

        expect(mockOnChange).toHaveBeenCalledWith({
            filterId: 'startTime',
            filterLabel: 'Start Time',
            filters: [{ label: 'Last 10 minutes', value: '10' }],
            operator: undefined,
        });
    });

    it('should not call onChange when value has not changed from initial', () => {
        render(<StartTimeOmniFilter {...defaultProps} />);

        // Simulate changing back to the initial value
        act(() =>
            MockStartTimeFilter.onChange({
                label: 'Last 5 minutes',
                value: '5',
            }),
        );

        expect(mockOnChange).not.toHaveBeenCalled();
    });

    it('should reset startTime when onClick is called', () => {
        const { rerender } = render(<StartTimeOmniFilter {...defaultProps} />);

        // Change the value
        act(() =>
            MockStartTimeFilter.onChange({
                label: 'Last 10 minutes',
                value: '10',
            }),
        );

        // Click to reset
        act(() => MockStartTimeFilter.onClick());

        // Rerender with same value to verify reset
        rerender(<StartTimeOmniFilter {...defaultProps} />);

        // Changing back to initial should not trigger onChange
        act(() =>
            MockStartTimeFilter.onChange({
                label: 'Last 5 minutes',
                value: '5',
            }),
        );

        expect(mockOnChange).toHaveBeenCalledTimes(1);
    });
});
