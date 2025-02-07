import { objToQueryStr } from '..';

describe('objToQueryStr', () => {
    it('successfully generates a querystring using objToQueryStr 1', () => {
        const expectedResult = '?query1=test1&query2=test2';
        const result = objToQueryStr({
            query1: 'test1',
            query2: 'test2',
        });
        expect(result).toEqual(expectedResult);
    });

    it('successfully generates a querystring using objToQueryStr 2', () => {
        const expectedResult = '';
        const result = objToQueryStr({});
        expect(result).toEqual(expectedResult);
    });

    it('should build the expected string', () => {
        const params = {
            page: 0,
            size: 100,
            namespace: ['name-1', 'name-2'],
            id: undefined,
            key: null,
            pod: ['pod-1', 'pod-2'],
        };

        expect(objToQueryStr(params)).toEqual(
            '?page=0&size=100&namespace=name-1&namespace=name-2&pod=pod-1&pod=pod-2',
        );
    });

    it('should handle booleans', () => {
        const params = {
            isEnabled: true,
            isDisabled: false,
        };

        expect(objToQueryStr(params)).toEqual(
            '?isEnabled=true&isDisabled=false',
        );
    });
});
