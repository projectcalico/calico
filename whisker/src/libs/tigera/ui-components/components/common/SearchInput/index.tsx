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
    useMultiStyleConfig,
} from '@chakra-ui/react';

type SearchInputProps = {
    value: string;
    onChange: (value: string) => void;
    iconButtonProps?: IconButtonProps;
    ref?: RefObject<HTMLInputElement>;
} & Omit<InputProps, 'onChange' | 'value'>;

const SearchInput: React.FC<SearchInputProps> = forwardRef(
    ({ value, onChange, iconButtonProps, sx, ...rest }, ref) => {
        const styles = useMultiStyleConfig('SearchInput', rest);

        return (
            <InputGroup px={0} size={'sm'} sx={sx}>
                <Input
                    value={value}
                    sx={styles.input}
                    onChange={(event) => onChange(event.target.value)}
                    ref={ref}
                    id='search-input'
                    autoComplete='off'
                    {...rest}
                />
                <InputRightElement sx={styles.iconContainer}>
                    {value ? (
                        <IconButton
                            sx={styles.iconButton}
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
        );
    },
);

export default SearchInput;
