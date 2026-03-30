import { Checkbox } from '@/components/common/shadcn/checkbox';
import {
    Field,
    FieldContent,
    FieldDescription,
    FieldGroup,
    FieldLabel,
} from '@/components/common/shadcn/field';
import { Badge } from '@chakra-ui/react';

type NoPolicyCheckboxProps = {
    value: boolean;
    onChange: (value: boolean) => void;
};
const NoPolicyCheckbox = ({ value, onChange }: NoPolicyCheckboxProps) => (
    <FieldGroup className='mx-auto'>
        <Field orientation='horizontal'>
            <div className='mt-[2px]'>
                <Checkbox
                    id='no-policy-checkbox-desc'
                    name='no-policy-checkbox-desc'
                    checked={value}
                    onCheckedChange={onChange}
                />
            </div>
            <FieldContent>
                <FieldLabel
                    htmlFor='no-policy-checkbox-desc'
                    className='cursor-pointer'
                >
                    Filter by{' '}
                    <Badge
                        fontWeight='medium'
                        textTransform='none'
                        fontSize='sm'
                        variant='solid'
                    >
                        No Policy
                    </Badge>
                </FieldLabel>
                <FieldDescription>
                    {value
                        ? 'Uncheck to add a new query.'
                        : 'This filter will clear all existing queries.'}
                </FieldDescription>
            </FieldContent>
        </Field>
    </FieldGroup>
);

export default NoPolicyCheckbox;
