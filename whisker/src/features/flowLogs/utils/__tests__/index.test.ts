import { getV1Columns, getV2Columns, updateFirstFlowStartTime } from '..';

describe('utils', () => {
    describe('getV1Columns', () => {
        const mockLocalStorage = {
            removeItem: jest.fn(),
            setItem: jest.fn(),
        };

        beforeEach(() => {
            Object.defineProperty(window, 'localStorage', {
                value: mockLocalStorage,
                writable: true,
            });
            jest.clearAllMocks();
        });

        it('should handle empty v1StoredColumns string', () => {
            const result = getV1Columns('', 'test-key');

            expect(result).toEqual({
                start_time: false,
                end_time: false,
                action: false,
                source_namespace: false,
                source_name: false,
                dest_namespace: false,
                dest_name: false,
                protocol: false,
                dest_port: false,
                reporter: true,
            });
            expect(mockLocalStorage.removeItem).toHaveBeenCalledWith(
                'whisker-flow-logs-stream-columns',
            );
            expect(mockLocalStorage.setItem).toHaveBeenCalledWith(
                'test-key',
                JSON.stringify(result),
            );
        });

        it('should set specified columns to true when v1StoredColumns contains valid column names', () => {
            const v1Columns = ['start_time', 'action', 'protocol'];
            const result = getV1Columns(JSON.stringify(v1Columns), 'test-key');

            expect(result).toEqual({
                start_time: true,
                end_time: false,
                action: true,
                source_namespace: false,
                source_name: false,
                dest_namespace: false,
                dest_name: false,
                protocol: true,
                dest_port: false,
                reporter: true,
            });

            expect(mockLocalStorage.removeItem).toHaveBeenCalledWith(
                'whisker-flow-logs-stream-columns',
            );
            expect(mockLocalStorage.setItem).toHaveBeenCalledWith(
                'test-key',
                JSON.stringify(result),
            );
        });

        it('should handle empty array in v1StoredColumns', () => {
            const result = getV1Columns(JSON.stringify([]), 'test-key');

            expect(result).toMatchObject({
                reporter: true,
            });
        });
    });

    describe('getV2Columns', () => {
        const mockLocalStorage = {
            removeItem: jest.fn(),
            setItem: jest.fn(),
        };

        beforeEach(() => {
            Object.defineProperty(window, 'localStorage', {
                value: mockLocalStorage,
                writable: true,
            });
            jest.clearAllMocks();
        });

        it('should add new columns', () => {
            const storedString = JSON.stringify({
                start_time: true,
                end_time: false,
            });

            const result = getV2Columns(storedString, 'test-key', {
                start_time: true,
                end_time: true,
                reporter: true,
            } as any);

            const expected = {
                start_time: true,
                end_time: false,
                reporter: true,
            };
            expect(result).toEqual(expected);
            expect(mockLocalStorage.setItem).toHaveBeenCalledWith(
                'test-key',
                JSON.stringify(expected),
            );
        });

        it('should remove old columns', () => {
            const storedString = JSON.stringify({
                start_time: true,
                end_time: true,
            });

            const result = getV2Columns(storedString, 'test-key', {
                start_time: true,
            } as any);

            const expected = {
                start_time: true,
            };
            expect(result).toEqual(expected);
            expect(mockLocalStorage.setItem).toHaveBeenCalledWith(
                'test-key',
                JSON.stringify(expected),
            );
        });

        it('should use the initial value when there is no stored string', () => {
            const result = getV2Columns('', 'test-key', {
                start_time: true,
            } as any);

            const expected = {
                start_time: true,
            };
            expect(result).toEqual(expected);
            expect(mockLocalStorage.setItem).toHaveBeenCalledWith(
                'test-key',
                JSON.stringify(expected),
            );
        });
    });
});

describe('updateFirstFlowStartTime', () => {
    const mockSetFirstFlowStartTime = jest.fn();

    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should set first flow start time to the earliest start time when filterFlowStartTime is null and data has items', () => {
        const baseTime = new Date('2024-01-01T12:00:00Z').getTime();
        const data = [
            {
                id: '1',
                start_time: new Date(baseTime + 2000), // 2 seconds later
                end_time: new Date(baseTime + 3000),
            } as any,
            {
                id: '2',
                start_time: new Date(baseTime - 1000), // 1 second earlier (earliest)
                end_time: new Date(baseTime + 1000),
            } as any,
            {
                id: '3',
                start_time: new Date(baseTime + 1000), // 1 second later
                end_time: new Date(baseTime + 2000),
            } as any,
        ];

        updateFirstFlowStartTime(data, null, mockSetFirstFlowStartTime);

        // The function sorts in descending order (latest first) and takes the last element (earliest)
        // Original order: [data[0]: +2000, data[1]: -1000, data[2]: +1000]
        // After descending sort: [data[0]: +2000, data[2]: +1000, data[1]: -1000]
        // So sorted[data.length - 1] = sorted[2] = data[1] (earliest time)
        expect(mockSetFirstFlowStartTime).toHaveBeenCalledWith(
            baseTime - 1000, // The earliest start time
        );
    });

    it('should not call setFirstFlowStartTime when filterFlowStartTime is not null', () => {
        const fixedTime = new Date('2024-01-01T12:00:00Z');
        const data = [
            {
                id: '1',
                start_time: fixedTime,
                end_time: new Date(fixedTime.getTime() + 1000),
            } as any,
        ];

        updateFirstFlowStartTime(data, 12345, mockSetFirstFlowStartTime);

        expect(mockSetFirstFlowStartTime).not.toHaveBeenCalled();
    });

    it('should not call setFirstFlowStartTime when data is empty', () => {
        updateFirstFlowStartTime([], null, mockSetFirstFlowStartTime);

        expect(mockSetFirstFlowStartTime).not.toHaveBeenCalled();
    });

    it('should handle single item in data array', () => {
        const fixedTime = new Date('2024-01-01T12:00:00Z');
        const data = [
            {
                id: '1',
                start_time: fixedTime,
                end_time: new Date(fixedTime.getTime() + 1000),
            } as any,
        ];

        updateFirstFlowStartTime(data, null, mockSetFirstFlowStartTime);

        expect(mockSetFirstFlowStartTime).toHaveBeenCalledWith(
            fixedTime.getTime(),
        );
    });
});
