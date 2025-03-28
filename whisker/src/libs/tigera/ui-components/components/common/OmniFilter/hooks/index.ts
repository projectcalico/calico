import { useLocation, useSearchParams } from 'react-router-dom';
import * as React from 'react';
import { OperatorType } from '../types';

/* 
    a hook which provides a collection of utility functions to read and change the url for Omnifilter operations
    aka allows Omnifilter to integrate with the url and use it as state (and changes to url will in turn update Omnifilter)
    this will also provide functions to work with the "page" param also used for any paginated results triggered by omnifilter
    
    This has two advantages over normal state storage:
    1. allows user to use browser back/fwd buttons on omni filter changes
    2. allows deep linking

    Example: where we have 3 omnifilters expressed by an enum:

        enum MyUrlFilterParam {
            sheep = 'sheep',
            dolphin = 'dolphin',
            car = 'car'
        }

        // defaultOperatorType can be specified for each filter type in an object like this:
        // note: defaultOperatorType is optional for each type
        const myFilterParamProperties = {
            [MyUrlFilterParam.sheep]: {
                defaultOperatorType: OperatorType.Equals,
            },
            [MyUrlFilterParam.dolphin]: {
                defaultOperatorType: OperatorType.NotEquals
            },
            etc
        }

        const [
            urlFilterParams,            // example, read state: {'banana': ['ford', 'tesla', 'kia'], 'sheep': ['ronanthesheep']}
            urlFilterOperatorParams,    // example, read state (for ops): {'banana': '=', 'sheep': '!='}
            setFilterParam,             // example, set state: when Omnifilter onChange: setFilterParam('banana', ['mercedes', 'tesla'], OperatorType.Equals)
            clearFilterParams,          // example, on Omnifilter reset: clearFilterParams() will clear url (and state)
            getAllUrlParamsAsString,
            getUrlParam,                // for utilising this state to get and set non-omnifilter params (like page, or anything else you need persisted)
            setUrlParam,
            setUrlParams        
        ] = useOmniFilterUrlState<typeof MyUrlFilterParam>(
            MyUrlFilterParam,
            myFilterParamProperties
        );

        // side note: a nice pattern is to enhanve myFilterParamProperties to be an enum/object with declarative properties keyed
        by your filters for driving other functionality (including defaultOperatorType) in a single place
*/

const OPERATOR_POSTFIX = 'op';
const PAGE_PARAM = 'page';

const getOperatorTypeFromString = (op: string): OperatorType | undefined => {
    const operatorKey = Object.keys(OperatorType).find(
        (key) => OperatorType[key as keyof typeof OperatorType] === op,
    );

    if (operatorKey) {
        return OperatorType[operatorKey as keyof typeof OperatorType];
    }

    return undefined;
};

type OmniFilterUrlStateFns = [
    Record<string, Array<string>>,
    Record<string, OperatorType>,
    (
        urlParam: string,
        values: Array<string>,
        operator: OperatorType | undefined,
    ) => void,
    () => void,
    () => string,
    (urlParam: string) => string | null,
    (urlParam: string, value: string | null) => void,
    (urlParams: Array<string>, values: Array<string | null>) => void,
];

export const useOmniFilterUrlState = <
    FILTER_PARAMS_ENUM extends Record<string, string>,
>(
    filterUrlParams: FILTER_PARAMS_ENUM,
    defaultOperatorTypeByFilterParam: Record<
        string,
        { defaultOperatorType?: OperatorType }
    >,
    urlParamPostfix?: string,
): OmniFilterUrlStateFns => {
    const routerLocation = useLocation();
    const [params, setSearchParams] = useSearchParams();
    const paramPostfix = urlParamPostfix ? `-${urlParamPostfix}` : '';

    const getUrlParam = (urlParam: string) =>
        params.get(`${urlParam}${paramPostfix}`) as string | null;

    const setUrlParam = (
        urlParam: string,
        value: string | null, // null removes the entry
    ) => {
        const key = `${urlParam}${paramPostfix}`;
        if (value) {
            params.set(key, value);
        } else {
            params.delete(key);
        }

        setSearchParams(params);
    };

    const setUrlParams = (
        urlParams: Array<string>,
        values: Array<string | null>, // null item removes the entry
    ) => {
        urlParams.forEach((urlParam, index) => {
            const key = `${urlParam}${paramPostfix}`;

            if (values[index] !== null) {
                params.set(key, values[index] as string);
            } else {
                params.delete(key);
            }
        });

        setSearchParams(params);
    };

    const getUrlParams = (urlParam: string) =>
        params.getAll(`${urlParam}${paramPostfix}`);

    const setFilterParam = (
        urlParam: string,
        values: Array<string>,
        operator: OperatorType | undefined,
    ) => {
        const key = `${urlParam}${paramPostfix}`;

        params.delete(key);
        values.forEach((value) => {
            params.append(key, value);
        });

        if (operator) {
            params.set(
                `${urlParam}-${OPERATOR_POSTFIX}${paramPostfix}`,
                operator,
            );
        }

        params.delete(`${PAGE_PARAM}${paramPostfix}`);

        setSearchParams(params);
    };

    const getAllUrlParamsAsString = () => params.toString();

    const getUrlOperatorParam = (
        urlParam: string,
    ): OperatorType | undefined => {
        const op = params.get(`${urlParam}-${OPERATOR_POSTFIX}${paramPostfix}`);

        if (op) {
            return (
                getOperatorTypeFromString(op) ||
                defaultOperatorTypeByFilterParam[urlParam].defaultOperatorType
            );
        } else {
            return defaultOperatorTypeByFilterParam[urlParam]
                .defaultOperatorType;
        }
    };

    const getFilterParams = () =>
        Object.values(filterUrlParams as object).reduce(
            (acc: any, filterParam: string) => {
                const paramValues = getUrlParams(filterParam);

                if (paramValues.length > 0) {
                    acc[filterParam] = paramValues;
                }

                return acc;
            },
            {},
        );

    const getFilterOperatorParams = () =>
        Object.values(filterUrlParams as object).reduce(
            (acc: any, filterParam: string) => {
                const opParam = getUrlOperatorParam(filterParam);
                if (opParam) {
                    acc[filterParam] = opParam;
                }

                return acc;
            },
            {},
        );

    const clearFilterParams = () => {
        Object.values(filterUrlParams as object).forEach((filterParam) => {
            params.delete(`${filterParam}${paramPostfix}`);
            params.delete(`${filterParam}-${OPERATOR_POSTFIX}${paramPostfix}`);
        });

        params.delete(`${PAGE_PARAM}${paramPostfix}`);

        setSearchParams(params);
    };

    const [urlFilterParams, setUrlFilterParams] =
        React.useState<Record<string, Array<string>>>(getFilterParams());

    const [urlFilterOperatorParams, setUrlFilterOperatorParams] =
        React.useState<Record<string, OperatorType>>(getFilterOperatorParams());

    // bind route params (and any changes to these) to local state
    React.useEffect(() => {
        setUrlFilterParams(getFilterParams());
        setUrlFilterOperatorParams(getFilterOperatorParams());
    }, [routerLocation.search]);

    return [
        urlFilterParams,
        urlFilterOperatorParams,
        setFilterParam,
        clearFilterParams,
        getAllUrlParamsAsString,
        getUrlParam,
        setUrlParam,
        setUrlParams,
    ];
};
