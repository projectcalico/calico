import { Box, Flex, Switch, forwardRef } from '@chakra-ui/react';
import React from 'react';
import { OmniFilterOption, OmniInternalListComponentProps } from '../../types';
import { listContainerStyles, switchStyles } from './styles';

export type OmniSwitchProps = {} & OmniInternalListComponentProps;

const OmniSwitchList: React.FC<OmniSwitchProps> = forwardRef(
    ({ options = [], selectedOptions, onChange, _height, ...rest }, ref) => {
        const [filters, setFilters] = React.useState<OmniFilterOption[]>([]);

        const handleOnChange = (
            event: { target: { checked: boolean } },
            option: OmniFilterOption,
        ) => {
            const updatedFilters = event.target.checked
                ? [...filters, option]
                : filters.filter((filter) => filter.value !== option.value);
            setFilters(updatedFilters);
            onChange(updatedFilters);
        };

        return (
            <Box data-testid='omni-switch-list'>
                <Flex sx={listContainerStyles} {...rest}>
                    {options.map((option, index) => (
                        <Switch
                            ref={index === 0 ? ref : undefined}
                            key={option.label}
                            data-testid={`omni-switch-list-switch-${index}`}
                            onChange={(e) => handleOnChange(e, option)}
                            isChecked={selectedOptions.some(
                                (selected) => selected.label === option.label,
                            )}
                            sx={switchStyles}
                        >
                            {option.label}
                        </Switch>
                    ))}
                </Flex>
            </Box>
        );
    },
);

export default OmniSwitchList;
