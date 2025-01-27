import { useCheckedTable } from '..';
import { act } from 'react-dom/test-utils';
import { render, screen } from '@/test-utils/helper';

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
});
