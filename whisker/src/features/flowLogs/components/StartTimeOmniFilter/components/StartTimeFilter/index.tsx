import {
    OmniFilterBody,
    OmniFilterContainer,
    OmniFilterContent,
    OmniFilterTrigger,
} from '@/libs/tigera/ui-components/components/common/OmniFilter/parts';
import { OmniFilterOption } from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import Select from '@/libs/tigera/ui-components/components/common/Select';

import React from 'react';
import OmniFilterFooter from '../../../OmniFilterFooter';

const testId = 'start-time';

type StartTimeFilterProps = {
    filterLabel: string;
    triggerLabel: string;
    value: OmniFilterOption;
    isActive: boolean;
    options: OmniFilterOption[];
    onChange: (value: OmniFilterOption) => void;
    onClick: () => void;
    onClear: () => void;
    onSubmit: () => void;
};

const StartTimeFilter: React.FC<StartTimeFilterProps> = ({
    filterLabel,
    triggerLabel,
    isActive,
    options,
    value,
    onClick,
    onChange,
    onClear,
    onSubmit,
}) => (
    <OmniFilterContainer>
        {({ onClose }) => (
            <>
                <OmniFilterTrigger
                    label={filterLabel}
                    testId={testId}
                    selectedValueLabel={triggerLabel}
                    onClick={() => {
                        onClick();
                    }}
                    isActive={isActive}
                />
                <OmniFilterContent data-testid={`${testId}-popover-content`}>
                    <OmniFilterBody
                        data-testid={`${testId}-popover-body`}
                        py={4}
                    >
                        <Select
                            options={options}
                            isSearchable={false}
                            isClearable={false}
                            value={value}
                            onChange={onChange}
                        />
                    </OmniFilterBody>

                    <OmniFilterFooter
                        testId={testId}
                        clearButtonProps={{
                            onClick: () => {
                                onClear();
                                onClose();
                            },
                        }}
                        submitButtonProps={{
                            onClick: () => {
                                onSubmit();
                                onClose();
                            },
                        }}
                    />
                </OmniFilterContent>
            </>
        )}
    </OmniFilterContainer>
);

export default StartTimeFilter;
