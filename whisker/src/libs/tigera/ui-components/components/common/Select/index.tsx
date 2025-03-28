import * as React from 'react';
import * as ReactSelect from 'chakra-react-select';
import styles from './styles';
import type { GroupBase, Props } from 'react-select';
import { Box, Flex, Icon, Image, forwardRef } from '@chakra-ui/react';

type Option = any;
type IsMulti = boolean;
type Group = GroupBase<Option>;
type ChakraStylesConfig = {
    sx?: ReactSelect.ChakraStylesConfig;
};
export type SelectType = Props<Option, IsMulti, Group> & ChakraStylesConfig;
export type CreatableSelectType = ReactSelect.CreatableProps<
    Option,
    IsMulti,
    Group
> &
    ChakraStylesConfig;

export type SelectOption = {
    label: string;
    value: string;
    iconUrl?: string;
};

// TODO this will require more tweaking depending on specific use cases - change it as required
// its not styled in the same way as a standard Chakra component...
// see here for more: https://github.com/csandman/chakra-react-select#readme

const Select: React.FC<React.PropsWithChildren<SelectType>> = forwardRef(
    ({ sx, isMulti = false, options, ...rest }, ref) => {
        const hasIcons = options?.every(
            (option: Option) =>
                option.icon !== undefined || option.iconUrl !== undefined,
        );

        return (
            <ReactSelect.Select
                ref={ref}
                isMulti={isMulti}
                options={options}
                {...((hasIcons
                    ? {
                          formatOptionLabel: (e: any) => (
                              <SelectIconOption
                                  icon={e.icon}
                                  iconUrl={e.iconUrl}
                                  label={e.label}
                              />
                          ),
                      }
                    : {}) as any)}
                {...rest}
                chakraStyles={{ ...styles, ...sx }}
            />
        );
    },
);

export const CreatableSelect: React.FC<CreatableSelectType> = ({
    sx,
    ...rest
}) => (
    <ReactSelect.CreatableSelect
        {...rest}
        chakraStyles={{ ...styles, ...sx }}
    />
);

export const SelectIconOption: React.FC<
    React.PropsWithChildren<{
        label: string;
        icon?: any;
        iconUrl?: string;
    }>
> = ({ icon, iconUrl, label }) => (
    <Flex alignItems='center'>
        {icon && <Icon as={icon} w={6} h={6} mr={2} />}
        {iconUrl && <Image src={iconUrl} w={6} h={6} />}
        <Box as='span' ml={2}>
            {label}
        </Box>
    </Flex>
);

export default Select;
