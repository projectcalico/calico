import React from 'react';
import Select from '../../../Select';
import { selectStyles } from './styles';
import type { SelectType } from '../../../Select';
import { OperatorType } from '../../types';

type OmniFilterOperatorSelectProps = {
    label: string;
    value: string;
    onChange: (value: string) => void;
} & SelectType;

const operatorLabels = {
    [OperatorType.Equals]: '(equals)',
    [OperatorType.NotEquals]: '(not equals)',
};

const OmniFilterOperatorSelect: React.FC<OmniFilterOperatorSelectProps> = ({
    label,
    value,
    onChange,
    ...rest
}) => {
    const options = Object.entries(operatorLabels).map(([key, value]) => ({
        label: `${label} ${key} ${value}`,
        value: key,
    }));

    return (
        <Select
            options={options}
            value={options.find((option) => option.value === value)}
            size={'sm'}
            onChange={(event) => onChange(event.value)}
            sx={selectStyles}
            variant='filled'
            {...rest}
        />
    );
};

export default OmniFilterOperatorSelect;
