import { Text } from '@/libs/tigera/ui-components/components/common';
import Pulse from '@/components/common/Pulse';

type FlowLogsTableEmptyMessageProps = {
    hasActiveFilters: boolean;
};

const FlowLogsTableEmptyMessage: React.FC<FlowLogsTableEmptyMessageProps> = ({
    hasActiveFilters,
}) => (
    <div>
        <div data-testid='empty-container' className='flex flex-col'>
            <Text size='xl' className='font-bold mb-4!'>
                Nothing to see yet.
            </Text>
            <div
                className='flex! gap-2! items-center! justify-center! flex-row! p-0!'
                data-testid='empty-container-flex-box'
            >
                <Pulse size='12px' padding='0!important' />
                <Text className=' text-tigera-token-fg-support'>
                    {hasActiveFilters
                        ? 'Waititing for flows that match the active filters.'
                        : 'Flows will start to appear shortly.'}
                </Text>
            </div>
        </div>
    </div>
);

export default FlowLogsTableEmptyMessage;
