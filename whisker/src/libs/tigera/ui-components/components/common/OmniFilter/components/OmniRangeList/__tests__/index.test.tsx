import { fireEvent, render, screen } from '@/test-utils/helper';
import OmniRangeList from '../index';
import '@testing-library/jest-dom';
import { OmniFilterOption } from '../../../types';

const options = [
    { label: 'CUSTOM LABEL 1', value: 'gte' },
    { label: 'CUSTOM LABEL 2', value: 'lte' },
];

const selectedOptions: OmniFilterOption[] = [
    { label: 'CUSTOM LABEL 1', value: 'gte:30' },
    { label: 'CUSTOM LABEL 2', value: 'lte:70' },
];

const onChange = jest.fn();

const defaultProps = {
    emptyMessage: '',
    showMoreButton: false,
    isLoadingMore: false,
};

describe('OmniRangeList Component', () => {
    it('should render the component with correct labels and inputs', () => {
        render(
            <OmniRangeList
                {...defaultProps}
                options={options}
                selectedOptions={selectedOptions}
                onChange={onChange}
            />,
        );

        expect(screen.getByText('CUSTOM LABEL 1')).toBeInTheDocument();
        expect(screen.getByText('CUSTOM LABEL 2')).toBeInTheDocument();

        expect(
            screen.getByTestId('omni-range-list-input-CUSTOM LABEL 1'),
        ).toBeInTheDocument();
        expect(
            screen.getByTestId('omni-range-list-input-CUSTOM LABEL 2'),
        ).toBeInTheDocument();
    });

    it('should call onChange with correct values when input changes', async () => {
        render(
            <OmniRangeList
                {...defaultProps}
                options={options}
                selectedOptions={selectedOptions}
                onChange={onChange}
            />,
        );

        const input1 = screen.getByTestId(
            'omni-range-list-input-CUSTOM LABEL 1',
        );
        const input2 = screen.getByTestId(
            'omni-range-list-input-CUSTOM LABEL 2',
        );

        fireEvent.change(input1, { target: { value: '50' } });
        fireEvent.blur(input1);

        await new Promise((resolve) => setTimeout(resolve, 1000));

        expect(onChange).toHaveBeenCalledWith([
            { label: 'CUSTOM LABEL 1', value: 'gte:50' },
            { label: 'CUSTOM LABEL 2', value: 'lte:70' },
        ]);

        fireEvent.change(input2, { target: { value: '60' } });
        fireEvent.blur(input2);

        expect(onChange).toHaveBeenCalledWith([
            { label: 'CUSTOM LABEL 1', value: 'gte:50' },
            { label: 'CUSTOM LABEL 2', value: 'lte:60' },
        ]);
    });
});
