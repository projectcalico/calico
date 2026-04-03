import { renderHook, act } from '@testing-library/react';
import { useFlowLogSort } from '..';

jest.mock('../../utils', () => ({
    ...jest.requireActual('../../utils'),
    getV1Columns: jest.fn(),
    getV2Columns: jest.fn(),
}));

describe('useFlowLogSort', () => {
    it('should initialise with the default sort state', () => {
        const { result } = renderHook(() => useFlowLogSort());

        expect(result.current.sortState).toEqual([
            { id: 'start_time', desc: true },
        ]);
        expect(result.current.defaultSortState).toEqual([
            { id: 'start_time', desc: true },
        ]);
    });

    it('should update sortState and call setSortBy on handleSort', () => {
        const setSortBy = jest.fn();
        const { result } = renderHook(() => useFlowLogSort());

        act(() => {
            result.current.handleSort(
                { id: 'action', isSorted: false },
                setSortBy,
            );
        });

        const expected = [
            { id: 'action', desc: false },
            { id: 'start_time', desc: true },
        ];
        expect(result.current.sortState).toEqual(expected);
        expect(setSortBy).toHaveBeenCalledWith(expected);
    });

    it('should use the updated sortState for consecutive sorts', () => {
        const setSortBy = jest.fn();
        const { result } = renderHook(() => useFlowLogSort());

        act(() => {
            result.current.handleSort(
                { id: 'action', isSorted: false },
                setSortBy,
            );
        });

        act(() => {
            result.current.handleSort(
                { id: 'action', isSorted: true, isSortedDesc: false },
                setSortBy,
            );
        });

        expect(result.current.sortState).toEqual([
            { id: 'action', desc: true },
            { id: 'start_time', desc: true },
        ]);
    });
});
