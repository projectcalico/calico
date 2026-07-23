import { Checkbox } from '@/components/common/shadcn/checkbox';
import {
    Field,
    FieldContent,
    FieldDescription,
    FieldGroup,
    FieldLabel,
} from '@/components/common/shadcn/field';
import { InfoOutlineIcon } from '@chakra-ui/icons';
import { Badge, Tooltip } from '@chakra-ui/react';

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
                <div className='flex items-center gap-2'>
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
                    <Tooltip label='Show flows where only default profile rules were evaluated, with no explicit policies applied.'>
                        <InfoOutlineIcon
                            color='experimental-token-fg-subtle'
                            boxSize={3}
                        />
                    </Tooltip>
                </div>
                <FieldDescription>
                    {value
                        ? 'Uncheck to add a new filter.'
                        : 'This filter will clear any existing filters.'}
                </FieldDescription>
            </FieldContent>
        </Field>
    </FieldGroup>
);

export default NoPolicyCheckbox;
