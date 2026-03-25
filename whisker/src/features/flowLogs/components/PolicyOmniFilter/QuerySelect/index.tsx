import { OmniFilterOption } from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import { Text } from '@/libs/tigera/ui-components/components/common/text';
import { FilterHintKey } from '@/utils/omniFilter';
import PolicySelect from '../PolicySelect';

type QuerySelectProps = {
    label: string;
    filterKey: FilterHintKey;
    value: OmniFilterOption | null | undefined;
    onChange: (value: OmniFilterOption | null) => void;
    showSearch?: boolean;
};

const QuerySelect = ({
    label,
    filterKey,
    value,
    onChange,
    showSearch = true,
}: QuerySelectProps) => (
    <div className='flex justify-between items-center'>
        <Text className='flex-1' size='sm'>
            {label}
        </Text>
        <div className='flex-2'>
            <PolicySelect
                filterKey={filterKey}
                value={value}
                onChange={onChange}
                showSearch={showSearch}
            />
        </div>
    </div>
);

export default QuerySelect;
