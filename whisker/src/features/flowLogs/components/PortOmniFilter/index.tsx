import {
    OmniFilterBody,
    OmniFilterContainer,
    OmniFilterContent,
    OmniFilterTrigger,
} from '@/libs/tigera/ui-components/components/common/OmniFilter/parts';
import Select from '@/libs/tigera/ui-components/components/common/Select';
import { useDidUpdate } from '@/libs/tigera/ui-components/hooks';
import { CustomOmniFilterParam } from '@/utils/omniFilter';
import {
    Box,
    Center,
    Flex,
    FormControl,
    FormHelperText,
    FormLabel,
    Input,
} from '@chakra-ui/react';
import React from 'react';
import { Controller, useForm } from 'react-hook-form';
import FilterFooter from '../OmniFilterFooter';

type PortOmniFilterProps = {
    port: string;
    protocol: string;
    isDisabled?: boolean;
    selectedFilters: string[] | null;
    filterLabel: string;
    filterId: CustomOmniFilterParam;
    onChange: (event: { protocol: string | null; port: string | null }) => void;
};

const validOptions = [
    { label: 'TCP', value: 'tcp' },
    { label: 'UDP', value: 'udp' },
];
const options = [{ label: 'Any', value: '' }, ...validOptions];
const testId = 'port-filter';

const PortOmniFilter: React.FC<PortOmniFilterProps> = ({
    onChange,
    port = '',
    protocol = '',
    isDisabled = false,
}) => {
    const popoverContentRef = React.useRef<HTMLElement>(null);
    const initialFocusRef = React.useRef<HTMLInputElement>(null);
    const protocolLabel =
        validOptions.find((option) => option.value === protocol)?.label ?? '';
    const portLabel = isNaN(+port) ? '' : port;

    const {
        control,
        register,
        handleSubmit,
        formState: { errors, isValid, isDirty },
        reset,
        setValue,
    } = useForm({
        defaultValues: {
            port,
            protocol,
        },
        mode: 'onChange',
        reValidateMode: 'onChange',
    });

    useDidUpdate(() => {
        setValue('protocol', protocol);
    }, [protocol]);

    useDidUpdate(() => {
        setValue('port', port);
    }, [port]);

    return (
        <>
            <OmniFilterContainer initialFocusRef={initialFocusRef}>
                {({ isOpen, onClose }) => (
                    <>
                        <OmniFilterTrigger
                            isOpen={isOpen}
                            onClick={() =>
                                reset({
                                    port,
                                    protocol,
                                })
                            }
                            label='Port'
                            isActive={!!(portLabel || protocol)}
                            isDisabled={isDisabled}
                            testId={testId}
                            selectedValueLabel={[protocolLabel, portLabel]
                                .filter(Boolean)
                                .join(':')}
                        />
                        <OmniFilterContent ref={popoverContentRef}>
                            <form
                                onSubmit={handleSubmit(({ port, protocol }) => {
                                    onChange({
                                        protocol: protocol || null,
                                        port: String(port) || null,
                                    });
                                    onClose();
                                })}
                            >
                                <OmniFilterBody
                                    data-testid={`${testId}-popover-body`}
                                    py={4}
                                >
                                    <Flex gap={4} alignItems='start'>
                                        <FormControl isInvalid={false}>
                                            <FormLabel
                                                sx={{
                                                    fontWeight: '700',
                                                    fontSize: 'xs',
                                                }}
                                                htmlFor='protocol'
                                            >
                                                Protocol
                                            </FormLabel>
                                            <Box position='relative'>
                                                <Controller
                                                    name='protocol'
                                                    control={control}
                                                    render={({ field }) => (
                                                        <Select
                                                            id='protocol'
                                                            options={options}
                                                            value={options.find(
                                                                (option) =>
                                                                    option.value ===
                                                                    field.value,
                                                            )}
                                                            onChange={(
                                                                option,
                                                            ) =>
                                                                field.onChange(
                                                                    option.value,
                                                                )
                                                            }
                                                        />
                                                    )}
                                                />

                                                <Center
                                                    position='absolute'
                                                    right={-4}
                                                    top={0}
                                                    fontSize='md'
                                                    fontWeight='bold'
                                                    height='42px'
                                                    width={4}
                                                >
                                                    :
                                                </Center>
                                            </Box>
                                        </FormControl>

                                        <FormControl>
                                            <FormLabel
                                                sx={{
                                                    fontWeight: '700',
                                                    fontSize: 'xs',
                                                }}
                                                htmlFor='port'
                                            >
                                                Port
                                            </FormLabel>
                                            <Input
                                                type='number'
                                                height='42px'
                                                placeholder='8080'
                                                id='port'
                                                {...register('port', {
                                                    min: 1,
                                                    max: 65535,
                                                })}
                                            />

                                            {!!errors.port && (
                                                <FormHelperText
                                                    data-testid={`${testId}-error-message`}
                                                >
                                                    {errors.port?.type === 'min'
                                                        ? 'Min: 1'
                                                        : 'Max: 65536'}
                                                </FormHelperText>
                                            )}
                                        </FormControl>
                                    </Flex>
                                </OmniFilterBody>
                                <FilterFooter
                                    testId={testId}
                                    leftButtonProps={{
                                        onClick: () => {
                                            reset({
                                                port: '',
                                                protocol: '',
                                            });
                                            onChange({
                                                protocol: null,
                                                port: null,
                                            });
                                            onClose();
                                        },
                                    }}
                                    rightButtonProps={{
                                        disabled: !isDirty || !isValid,
                                        type: 'submit',
                                    }}
                                />
                            </form>
                        </OmniFilterContent>
                    </>
                )}
            </OmniFilterContainer>
        </>
    );
};

export default PortOmniFilter;
