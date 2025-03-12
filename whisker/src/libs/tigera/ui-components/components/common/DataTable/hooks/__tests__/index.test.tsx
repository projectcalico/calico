import { render, renderHook, screen } from '@/test-utils/helper';
import { act } from 'react-dom/test-utils';
import { useCheckedTable, useVirtualizedTableAnimationHelper } from '..';

let checkedTableData: any;

const TestUseCheckedTableHook = ({
    tableData,
    keyProp,
}: {
    tableData: any;
    keyProp?: any;
}) => {
    checkedTableData = useCheckedTable(tableData, keyProp);

    return <div>{JSON.stringify(checkedTableData)}</div>;
};

describe('hooks', () => {
    it('launches useCheckedTable', () => {
        render(
            <TestUseCheckedTableHook
                tableData={[
                    { name: 'mockEntry1' },
                    { name: 'mockEntry2' },
                    { name: 'mockEntry3' },
                ]}
                keyProp='name'
            />,
        );

        act(() => {
            checkedTableData.handleRowChecked({
                original: { name: 'mockEntry1' },
            });

            checkedTableData.handleRowChecked({
                original: { name: 'mockEntry3' },
            });
        });

        expect(
            screen.getByText(
                '{"checkedRows":["mockEntry1","mockEntry3"],"isAllChecked":false}',
            ),
        ).toBeInTheDocument();

        act(() => {
            checkedTableData.handleRowChecked({
                original: { name: 'mockEntry1' },
            });
        });

        expect(
            screen.getByText(
                '{"checkedRows":["mockEntry3"],"isAllChecked":false}',
            ),
        ).toBeInTheDocument();

        act(() => {
            checkedTableData.handleAllChecked();
        });

        expect(
            screen.getByText(
                '{"checkedRows":["mockEntry1","mockEntry2","mockEntry3"],"isAllChecked":true}',
            ),
        ).toBeInTheDocument();

        act(() => {
            checkedTableData.handleAllChecked();
        });

        expect(
            screen.getByText('{"checkedRows":[],"isAllChecked":false}'),
        ).toBeInTheDocument();
    });

    it('launches useCheckedTable using default keyProp', () => {
        render(
            <TestUseCheckedTableHook
                tableData={[
                    { id: 'mockEntry1' },
                    { id: 'mockEntry2' },
                    { id: 'mockEntry3' },
                ]}
            />,
        );

        act(() => {
            checkedTableData.handleRowChecked({
                original: { id: 'mockEntry1' },
            });
        });

        expect(
            screen.getByText(
                '{"checkedRows":["mockEntry1"],"isAllChecked":false}',
            ),
        ).toBeInTheDocument();
    });

    describe('useVirtualizedTableAnimationHelper', () => {
        it('should return true when calling shouldAnimate', () => {
            const id = '123';
            const { result, rerender } = renderHook(
                ({ data, rows, keyProp }) =>
                    useVirtualizedTableAnimationHelper(data, rows, keyProp),
                {
                    initialProps: {
                        data: [],
                        rows: [],
                        keyProp: id,
                    } as any,
                },
            );

            rerender({
                data: [{ id }],
                rows: [{ original: { id } }],
                keyProp: 'id',
            });

            expect(result.current.shouldAnimate(id)).toEqual(true);
        });

        it('should not animate after calling handleCompleteAnimation', () => {
            const id = '123';
            const { result } = renderHook(
                ({ data, rows, keyProp }) =>
                    useVirtualizedTableAnimationHelper(data, rows, keyProp),
                {
                    initialProps: {
                        data: [{ id }],
                        rows: [{ original: { id } }],
                        keyProp: 'id',
                    } as any,
                },
            );

            expect(result.current.shouldAnimate(id)).toEqual(true);

            result.current.handleCompleteAnimation(id);

            expect(result.current.shouldAnimate(id)).toEqual(false);
        });
    });
});
