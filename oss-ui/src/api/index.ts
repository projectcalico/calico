import { objToQueryStr, QueryObject } from '@/libs/tigera/ui-components/utils';
import { ApiError } from '../types/api';

const API_URL = 'http://localhost:3002';

type ApiOptions = RequestInit & {
    queryParams?: QueryObject;
};

export const apiFetch = async <T>(
    path: string,
    { queryParams, ...options }: ApiOptions = {},
): Promise<T> => {
    try {
        let queryString = '';
        if (queryParams) {
            queryString = objToQueryStr(queryParams);
        }

        const response = await fetch(
            `${API_URL}/${path}${queryString}`,
            options,
        );

        if (response.ok) {
            return await response.json();
        } else {
            const apiError: ApiError = {
                data: await response.json(),
                response,
            };
            console.error('Error response returned from api', apiError);

            return Promise.reject(apiError);
        }
    } catch (error) {
        console.error('Error sending http request', error);
        return Promise.reject({});
    }
};

const get = <T>(path: string, options: ApiOptions = {}): Promise<T> => {
    return apiFetch(path, { method: 'get', ...options });
};

export default {
    get,
};
