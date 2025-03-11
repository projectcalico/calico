import * as React from 'react';
import { Row } from 'react-table';

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

export const useVirtualizedTableAnimationHelper = (
    data: any[],
    rows: Row<any>[],
    keyProp: string,
) => {
    const difference = React.useRef(0);
    const lastLength = React.useRef(0);
    const animatedRows = React.useRef<any[]>([]);
    const length = data.length;

    if (length - lastLength.current > 0) {
        difference.current = length - lastLength.current;
        lastLength.current = length;
        animatedRows.current = (rows as []).slice(0, difference.current);
    }

    const handleCompleteAnimation = (id: string) => {
        animatedRows.current = animatedRows.current.filter(
            (row) => row.original[keyProp] !== id,
        );
    };

    const shouldAnimate = (id: string) =>
        animatedRows.current.some((row) => row.original[keyProp] === id);

    return {
        handleCompleteAnimation,
        shouldAnimate,
    };
};
