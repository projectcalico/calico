import { renderHook } from '@/test-utils/helper';
import { useSelectedOmniFilters } from '..';
import {
    OmniFilterData,
    OmniFilterParam,
    SelectedOmniFilterData,
} from '@/utils/omniFilter';

const urlFilterParams: Record<OmniFilterParam, string[]> = {
    namespace: ['foo'],
    policy: [],
    source_namespace: [],
    dest_namespace: [],
};
const omniFilterData: OmniFilterData = {
    namespace: {
        filters: [
            { label: 'Foo', value: 'foo' },
            { label: 'Bar', value: 'bar' },
        ],
        isLoading: false,
    },
    policy: {
        filters: [],
        isLoading: false,
    },
    dest_namespace: {
        filters: [],
        isLoading: false,
    },
    source_namespace: {
        filters: [],
        isLoading: false,
    },
};
const selectedOmniFilterData: SelectedOmniFilterData = {
    namespace: {
        filters: [{ label: 'Foo', value: 'foo' }],
        isLoading: false,
        total: 0,
    },
};

describe('useSelectedOmniFilters', () => {
    it('should get selected option from selectedOmniFilterData', () => {
        const { result } = renderHook(() =>
            useSelectedOmniFilters(
                urlFilterParams,
                omniFilterData,
                selectedOmniFilterData,
            ),
        );

        expect(result.current).toEqual({
            namespace: [{ label: 'Foo', value: 'foo' }],
            policy: [],
            dest_namespace: [],
            source_namespace: [],
        });
    });

    it('should get selected option from omniFilterData', () => {
        const selectedOmniFilterData: SelectedOmniFilterData = {
            namespace: {
                filters: [],
                isLoading: false,
                total: 0,
            },
        };

        const { result } = renderHook(() =>
            useSelectedOmniFilters(
                urlFilterParams,
                omniFilterData,
                selectedOmniFilterData,
            ),
        );

        expect(result.current).toEqual({
            namespace: [{ label: 'Foo', value: 'foo' }],
            policy: [],
            dest_namespace: [],
            source_namespace: [],
        });
    });

    it('should create an option from the value when there is no option omniFilterData', () => {
        const omniFilterData: OmniFilterData = {
            namespace: {
                filters: [],
                isLoading: false,
            },
            policy: {
                filters: [],
                isLoading: false,
            },
            dest_namespace: {
                filters: [],
                isLoading: false,
            },
            source_namespace: {
                filters: [],
                isLoading: false,
            },
        };
        const selectedOmniFilterData: SelectedOmniFilterData = {
            namespace: {
                filters: [],
                isLoading: false,
                total: 0,
            },
        };

        const { result } = renderHook(() =>
            useSelectedOmniFilters(
                urlFilterParams,
                omniFilterData,
                selectedOmniFilterData,
            ),
        );

        expect(result.current).toEqual({
            namespace: [{ label: 'foo', value: 'foo' }],
            policy: [],
            dest_namespace: [],
            source_namespace: [],
        });
    });
});
