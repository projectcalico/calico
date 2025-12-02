import OmniFilterFooter from '@/features/flowLogs/components/OmniFilterFooter';
import {
    OmniFilterBody,
    OmniFilterContainer,
    OmniFilterContent,
    OmniFilterTrigger,
} from '@/libs/tigera/ui-components/components/common/OmniFilter/parts';
import { OmniFilterOption } from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import Select from '@/libs/tigera/ui-components/components/common/Select';
import HiddenControl from '@/libs/tigera/ui-components/components/common/Select/components/HiddenControl';
import { SelectStyles } from '@/libs/tigera/ui-components/components/common/Select/styles';
import React from 'react';
import * as ReactSelect from 'chakra-react-select';

const testId = 'start-time';

type StartTimeFilterProps = {
    filterLabel: string;
    triggerLabel: string;
    value: OmniFilterOption;
    isActive: boolean;
    options: OmniFilterOption[];
    hasChanged: boolean;
    onChange: (value: OmniFilterOption) => void;
    onClick: () => void;
    onReset: () => void;
};

const StartTimeFilter: React.FC<StartTimeFilterProps> = ({
    filterLabel,
    triggerLabel,
    isActive,
    options,
    value,
    hasChanged,
    onClick,
    onChange,
    onReset,
}) => {
    const initialFocusRef = React.useRef<ReactSelect.SelectInstance>(null);

    return (
        <OmniFilterContainer initialFocusRef={initialFocusRef}>
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
                    <OmniFilterContent
                        data-testid={`${testId}-popover-content`}
                    >
                        <OmniFilterBody
                            data-testid={`${testId}-popover-body`}
                            px={0}
                            py={2}
                        >
                            <Select
                                options={options}
                                ref={initialFocusRef}
                                autoFocus
                                backspaceRemovesValue={false}
                                components={{
                                    Control: HiddenControl,
                                }}
                                controlShouldRenderValue={false}
                                hideSelectedOptions={false}
                                isClearable={false}
                                menuIsOpen
                                onChange={(newValue) => {
                                    onChange(newValue);
                                    onClose();
                                }}
                                placeholder='Select a start time...'
                                tabSelectsValue={false}
                                value={value}
                                sx={{
                                    menu: (styles) => ({
                                        ...styles,
                                        ...SelectStyles.menu,
                                        position: 'relative',
                                        my: 0,
                                        borderRadius: 0,
                                    }),
                                    menuList: (styles) => ({
                                        ...styles,
                                        ...SelectStyles.menuList,
                                        borderRadius: 0,
                                    }),
                                    option: (styles) => ({
                                        ...styles,
                                        ...SelectStyles.option,
                                        _dark: {
                                            ...SelectStyles.option._dark,
                                            background: 'tigeraGrey.1000',
                                        },
                                    }),
                                }}
                            />
                        </OmniFilterBody>
                        <OmniFilterFooter
                            testId={testId}
                            leftButtonProps={{
                                onClick: () => {
                                    onReset();
                                    onClose();
                                },
                                children: 'Reset filter',
                                isDisabled: !hasChanged,
                            }}
                        />
                    </OmniFilterContent>
                </>
            )}
        </OmniFilterContainer>
    );
};

export default StartTimeFilter;
