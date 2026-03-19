import {
    Accordion,
    AccordionContent,
    AccordionItem,
    AccordionTrigger,
} from '@/components/common/shadcn/accordion';
import { SelectOption } from '@/libs/tigera/ui-components/components/common/Select';
import { Text } from '@/libs/tigera/ui-components/components/common/text';
import { CloseIcon } from '@chakra-ui/icons';
import { Box, Button, Tooltip } from '@chakra-ui/react';
import React from 'react';
import QuerySelect from '../QuerySelect';
import QueryLabel from '../QueryLabel';
import { FilterKey } from '@/utils/omniFilter';
import { getDefaultExpanded, updateQueryField } from '../utils';

export type Query = {
    kind: string;
    tier: string;
    namespace: string;
    name: string;
};

export type PolicyFilterKey = 'kind' | 'tier' | 'namespace' | 'name';

export type PolicyQuery = Partial<Record<PolicyFilterKey, SelectOption | null>>;

export type QuerySelect = Partial<Record<PolicyFilterKey, SelectOption | null>>;

type QueryListProps = {
    queries: QuerySelect[];
    onChange: (value: QuerySelect[]) => void;
};

const QueryList = ({ queries, onChange }: QueryListProps) => {
    const defaultExpanded = React.useMemo(
        () => getDefaultExpanded(queries),
        [],
    );
    const [expandedValue, setExpandedValue] =
        React.useState<string>(defaultExpanded);

    const updateField =
        (index: number, field: keyof QuerySelect) =>
        (changedValue: SelectOption | null) =>
            onChange(updateQueryField(queries, index, field, changedValue));

    const addQuery = () => {
        const newState = [...queries, {}];
        setExpandedValue(String(newState.length - 1));
        onChange(newState);
    };

    const onDeleteQuery = (index: number) => (event: any) => {
        event.stopPropagation();
        onChange(queries.toSpliced(index, 1));
    };

    return (
        <div className='flex flex-col gap-4'>
            <Accordion
                type='single'
                collapsible
                value={expandedValue}
                onValueChange={setExpandedValue}
                className='flex flex-col gap-2'
            >
                {queries.map((query, index) => {
                    const itemValue = String(index);

                    return (
                        <>
                            <AccordionItem
                                key={itemValue}
                                value={itemValue}
                                className='border! border-tigera-token-border-default! rounded-md!'
                            >
                                <AccordionTrigger>
                                    <QueryLabel query={query} />
                                    <Tooltip label='Delete query'>
                                        <Box
                                            as='span'
                                            role='button'
                                            aria-label='Delete query'
                                            ml='auto'
                                            display='inline-flex'
                                            alignItems='center'
                                            justifyContent='center'
                                            cursor='pointer'
                                            onClick={onDeleteQuery(index)}
                                        >
                                            <CloseIcon fontSize='2xs' />
                                        </Box>
                                    </Tooltip>
                                </AccordionTrigger>
                                <AccordionContent className='flex flex-col gap-2 px-4'>
                                    <QuerySelect
                                        label='Kind'
                                        filterKey={FilterKey.policyKind}
                                        value={query.kind}
                                        onChange={updateField(index, 'kind')}
                                        showSearch={false}
                                    />
                                    <QuerySelect
                                        label='Tier'
                                        filterKey={FilterKey.policyTier}
                                        value={query.tier}
                                        onChange={updateField(index, 'tier')}
                                    />
                                    <QuerySelect
                                        label='Namespace'
                                        filterKey={FilterKey.policyNamespace}
                                        value={query.namespace}
                                        onChange={updateField(
                                            index,
                                            'namespace',
                                        )}
                                    />
                                    <QuerySelect
                                        label='Name'
                                        filterKey={FilterKey.policyName}
                                        value={query.name}
                                        onChange={updateField(index, 'name')}
                                    />
                                </AccordionContent>
                            </AccordionItem>

                            {index !== queries.length - 1 && (
                                <Text className='w-full text-center text-tigera-token-fg-support text-sm py-2'>
                                    or
                                </Text>
                            )}
                        </>
                    );
                })}
            </Accordion>

            <Tooltip
                label='You can add up to 5 queries.'
                isDisabled={queries.length < 5}
            >
                <Button
                    variant='neutral'
                    w='full'
                    minHeight='40px'
                    fontSize='sm'
                    onClick={addQuery}
                    disabled={queries.length >= 5}
                >
                    + Add Query
                </Button>
            </Tooltip>
        </div>
    );
};

export default QueryList;
