import * as React from 'react';

export type CheckedTableData = ReturnType<typeof useCheckedTable>;

export const useCheckedTable = (
    tableData: Array<any> | undefined,
    keyProp: string = 'id',
) => {
    const [checkedRows, setCheckedRows] = React.useState([] as Array<string>);
    const isAllChecked =
        tableData &&
        tableData.length > 0 &&
        tableData.length === checkedRows.length;

    const handleRowChecked = (row: { original: any }) => {
        const rowId = row.original[keyProp];
        if (!checkedRows.includes(rowId)) {
            setCheckedRows((prevState) => [...prevState, rowId]);
        } else {
            setCheckedRows((prevState) => {
                prevState.splice(
                    checkedRows.findIndex((i) => i === rowId),
                    1,
                );

                return [...prevState];
            });
        }
    };

    const handleAllChecked = () => {
        if (tableData) {
            if (checkedRows.length === tableData.length) {
                setCheckedRows([]);
            } else {
                setCheckedRows(tableData.map((data) => data[keyProp]));
            }
        }
    };

    return {
        checkedRows,
        setCheckedRows,
        isAllChecked,
        handleRowChecked,
        handleAllChecked,
    };
};
