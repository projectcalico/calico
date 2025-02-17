import React, { RefObject } from 'react';
import { CloseIcon, SearchIcon } from '@chakra-ui/icons';
import {
    IconButton,
    IconButtonProps,
    Input,
    InputGroup,
    InputProps,
    InputRightElement,
    forwardRef,
} from '@chakra-ui/react';
import { iconButtonStyles, iconContainerStyles, inputStyles } from './styles';

type SearchInputProps = {
    value: string;
    onChange: (value: string) => void;
    iconButtonProps?: IconButtonProps;
    ref?: RefObject<HTMLInputElement>;
} & Omit<InputProps, 'onChange' | 'value'>;

const SearchInput: React.FC<SearchInputProps> = forwardRef(
    ({ value, onChange, iconButtonProps, sx, ...rest }, ref) => (
        <InputGroup px={0} size={'sm'} sx={sx}>
            <Input
                value={value}
                variant='flushed'
                sx={inputStyles}
                onChange={(event) => onChange(event.target.value)}
                ref={ref}
                {...rest}
            />
            <InputRightElement sx={iconContainerStyles}>
                {value ? (
                    <IconButton
                        sx={iconButtonStyles}
                        icon={<CloseIcon />}
                        variant={'icon'}
                        onClick={() => {
                            onChange('');
                            (ref as any)?.current?.focus();
                        }}
                        aria-label={
                            iconButtonProps?.['aria-label'] ?? 'Clear text'
                        }
                        {...iconButtonProps}
                    />
                ) : (
                    <SearchIcon />
                )}
            </InputRightElement>
        </InputGroup>
    ),
);

export default SearchInput;
