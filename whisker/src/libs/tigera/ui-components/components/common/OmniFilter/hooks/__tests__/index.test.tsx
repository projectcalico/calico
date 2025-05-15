import { act, renderHookWithRouter } from '@/test-utils/helper';
import { useSearchParams } from 'react-router-dom';
import { useOmniFilterUrlState } from '../';
import { OperatorType } from '../../types';

describe('useOmniFilterUrlState', () => {
    const filterUrlParams = {
        sheep: 'sheep',
        dolphin: 'dolphin',
    };

    const defaultOperatorTypeByFilterParam = {
        sheep: { defaultOperatorType: OperatorType.Equals },
        dolphin: { defaultOperatorType: OperatorType.NotEquals },
    };

    const renderHook = () =>
        renderHookWithRouter(
            () =>
                useOmniFilterUrlState(
                    filterUrlParams,
                    defaultOperatorTypeByFilterParam,
                ),
            {
                routes: ['/?sheep=ronanthesheep&dolphin=flipper&page=1'],
            },
        );

    afterEach(() => {
        jest.clearAllMocks();
    });

    test('initial state is set from URL params', () => {
        const {
            result: {
                current: [urlFilterParams, urlFilterOperatorParams],
            },
        } = renderHook();

        expect(urlFilterParams).toEqual({
            sheep: ['ronanthesheep'],
            dolphin: ['flipper'],
        });

        expect(urlFilterOperatorParams).toEqual({
            sheep: OperatorType.Equals,
            dolphin: OperatorType.NotEquals,
        });
    });

    test('setFilterParam updates URL and state correctly', () => {
        jest.mocked(useSearchParams);
        const { result } = renderHook();

        const [, , setFilterParam, , getAllUrlParamsAsString] = result.current;

        act(() => {
            setFilterParam('sheep', ['colmTheSheep'], OperatorType.Equals);
        });

        expect(getAllUrlParamsAsString()).toEqual(
            'dolphin=flipper&sheep=colmTheSheep&sheep-op=%3D',
        );
    });

    test('clearFilterParams clears the URL and state', () => {
        const {
            result: { current },
        } = renderHook();

        const [, , , clearFilterParams, getAllUrlParamsAsString] = current;

        act(() => {
            clearFilterParams();
        });

        expect(getAllUrlParamsAsString()).toEqual('');
    });

    test('getUrlParam retrieves correct value from URL', () => {
        const {
            result: { current },
        } = renderHook();

        const [, , , , , getUrlParam] = current;

        const value = getUrlParam('sheep');
        expect(value).toBe('ronanthesheep');
    });

    test('setUrlParam updates URL correctly', () => {
        const { result } = renderHook();

        const [, , , , getAllUrlParamsAsString, , setUrlParam] = result.current;

        // set page param
        act(() => {
            setUrlParam('page', '2');
        });

        expect(getAllUrlParamsAsString()).toEqual(
            'sheep=ronanthesheep&dolphin=flipper&page=2',
        );

        // reset page param
        act(() => {
            setUrlParam('anotherParam', 'abc');
        });

        expect(getAllUrlParamsAsString()).toEqual(
            'sheep=ronanthesheep&dolphin=flipper&page=2&anotherParam=abc',
        );
    });
});
