import { OmniFilterOption } from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import {
    OmniFilterData,
    OmniFilterParam,
    SelectedOmniFilterData,
    SelectedOmniFilterOptions,
} from '@/utils/omniFilter';

export const useSelectedOmniFilters = (
    urlFilterParams: Record<OmniFilterParam, string[]>,
    omniFilterData: OmniFilterData,
    selectedOmniFilterData: SelectedOmniFilterData,
) =>
    Object.keys(urlFilterParams as Record<OmniFilterParam, string[]>).reduce(
        (accumulator, current) => {
            const filterId: OmniFilterParam = current as OmniFilterParam;

            const selectedFilters = urlFilterParams[filterId].map(
                (selectedValue) => {
                    let selectedOption = selectedOmniFilterData?.[
                        filterId
                    ]?.filters?.find(
                        (data: OmniFilterOption) =>
                            data.value === selectedValue,
                    );

                    if (selectedOption) {
                        return selectedOption;
                    }

                    selectedOption = omniFilterData[filterId]?.filters?.find(
                        (selectOption) => selectOption.value === selectedValue,
                    ) ?? {
                        label: selectedValue,
                        value: selectedValue,
                    };

                    return selectedOption;
                },
            );

            accumulator[filterId] = selectedFilters;

            return accumulator;
        },
        {} as SelectedOmniFilterOptions,
    );
