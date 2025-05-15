import { render, screen } from '@/test-utils/helper';
import { ArrowDownIcon, ArrowUpIcon } from '@chakra-ui/icons';
import { Box } from '@chakra-ui/react';
import { fireEvent } from '@testing-library/react';
import React from 'react';
import Select, { CreatableSelect, SelectIconOption } from '../index';

jest.mock('chakra-react-select', () => ({
    Select: ({ options = [], onChange, isMulti, ...rest }: any) => {
        const [values, setValues] = React.useState<any[]>([]);
        const handleChange = (value: any) => {
            const option = options.find(
                (option: { value: string }) => option.value === value,
            );
            onChange(option);
        };

        const handleMultiChange = (value: any) => {
            const option = options.find(
                (option: { value: string }) => option.value === value,
            );
            const newValues = [...values, option];
            setValues(newValues);
            onChange(newValues);
        };

        return (
            <select data-testid='react-select' {...rest}>
                {options.map(({ label, value }: any) => (
                    <option
                        key={value}
                        value={value}
                        onClick={() =>
                            isMulti
                                ? handleMultiChange(value)
                                : handleChange(value)
                        }
                    >
                        {label}
                    </option>
                ))}
            </select>
        );
    },
    CreatableSelect: (props: any) => <Box {...props}>MockCreatableSelect</Box>,
}));

export const mockOptions = [
    { value: 'blue', label: 'Blue', color: '#0052CC' },
    { value: 'purple', label: 'Purple', color: '#5243AA' },
];

export const mockOptionsWithIcons = [
    {
        value: 'blue',
        label: 'Blue',
        color: '#0052CC',
        icon: ArrowUpIcon,
    },
    {
        value: 'purple',
        label: 'Purple',
        color: '#5243AA',
        icon: ArrowDownIcon,
    },
];

describe('<Select/>', () => {
    it('it renders with options', () => {
        const mockedOnChange = jest.fn();
        const { queryByTestId } = render(
            <div data-testid='my-select-component'>
                <Select
                    options={mockOptionsWithIcons}
                    onChange={mockedOnChange}
                />
            </div>,
        );

        const mySelectComponent = queryByTestId(
            'my-select-component',
        ) as HTMLElement;

        expect(mySelectComponent).toBeDefined();
        expect(mySelectComponent).not.toBeNull();
        expect(mockedOnChange).toHaveBeenCalledTimes(0);

        fireEvent.click(screen.getByTestId('react-select'));
        fireEvent.click(screen.getByText('Blue'));

        expect(mockedOnChange).toHaveBeenCalledTimes(1);
    });

    it('it renders with no options', () => {
        const { asFragment } = render(
            <div data-testid='my-select-component'>
                <Select />
            </div>,
        );
        expect(asFragment()).toMatchSnapshot();
    });

    it('it renders SelectIconOption with icon', () => {
        const { asFragment } = render(
            <div data-testid='my-select-component'>
                <SelectIconOption label={'test'} icon={ArrowUpIcon} />
            </div>,
        );
        expect(asFragment()).toMatchSnapshot();
    });

    it('it renders SelectIconOption with iconUrl', () => {
        const { asFragment } = render(
            <div data-testid='my-select-component'>
                <SelectIconOption label={'test'} iconUrl='fake-url' />
            </div>,
        );
        expect(asFragment()).toMatchSnapshot();
    });

    it('it renders with no options', () => {
        const { asFragment } = render(
            <div data-testid='my-select-component'>
                <Select
                    id='form-field'
                    name='colors'
                    selectedOptionStyle='check'
                    options={mockOptions}
                    isMulti={true}
                    placeholder='Select...'
                    closeMenuOnSelect={false}
                />
            </div>,
        );
        expect(asFragment()).toMatchSnapshot();
    });

    it('it renders creatable', () => {
        const { asFragment } = render(
            <div data-testid='my-select-component'>
                <CreatableSelect
                    id='form-field'
                    name='colors'
                    selectedOptionStyle='check'
                    options={mockOptions}
                    isMulti={true as any}
                    placeholder='Select...'
                    closeMenuOnSelect={false}
                />
                ,
            </div>,
        );
        expect(asFragment()).toMatchSnapshot();
    });

    it('it can select multiple values', () => {
        const mockOnChange = jest.fn();
        const { asFragment } = render(
            <div data-testid='my-select-component'>
                <Select
                    id='form-field'
                    name='colors'
                    selectedOptionStyle='check'
                    options={mockOptions}
                    isMulti={true as any}
                    placeholder='Select...'
                    closeMenuOnSelect={false}
                    classNamePrefix='multi'
                    onChange={mockOnChange}
                />
                ,
            </div>,
        );

        fireEvent.keyDown(
            screen.getByTestId('my-select-component').firstChild as any,
            {
                key: 'ArrowDown',
            },
        );
        fireEvent.click(screen.getByText('Blue'));
        fireEvent.keyDown(
            screen.getByTestId('my-select-component').firstChild as any,
            {
                key: 'ArrowDown',
            },
        );
        fireEvent.click(screen.getByText('Purple'));

        expect(mockOnChange).toHaveBeenCalledWith(mockOptions);
        expect(asFragment()).toMatchSnapshot();
    });
});
