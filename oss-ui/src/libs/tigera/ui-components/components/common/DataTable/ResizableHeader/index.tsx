import * as React from 'react';
import { Tr, Thead, Th, Flex, Center, Box, Checkbox } from '@chakra-ui/react';
import { ChevronRightIcon, ChevronLeftIcon } from '@chakra-ui/icons';
import type { SystemStyleObject } from '@chakra-ui/react';
import {
    resizerStyles,
    adjustBorderOnResizeStyles,
    resizingIconStyles,
    resizingContainerStyles,
    resizingIconFlexStyles,
    resizerSeperatorStyles,
    tableHeadStyles,
    checkboxStyles,
} from './styles';
import Sorter from './components/Sorter';
import { EXPANDO_COLUMN_ID } from '../ResizableBody';

interface ResizableHeaderProps {
    isFixed?: boolean;
    headerGroups: Array<any>;
    isAllChecked?: boolean;
    onAllChecked?: () => void;
    checkedRows?: Array<string>;
    sx?: SystemStyleObject;
    enableResize?: boolean;
    onSortCustomHandler?: (column: any) => void;
}

export enum SORT_DIRECTION {
    DESC = 'DESC',
    ASC = 'ASC',
    NONE = 'none',
}
export interface ServerSorting {
    accessor: string;
    sortDirection: SORT_DIRECTION;
}

const Resizer = () => (
    <Flex sx={resizingContainerStyles}>
        <Center sx={resizingIconFlexStyles}>
            <ChevronLeftIcon sx={resizingIconStyles} mr={2} />
        </Center>
        <Center sx={resizerSeperatorStyles} />
        <Center sx={resizingIconFlexStyles}>
            <ChevronRightIcon sx={resizingIconStyles} ml={2} />
        </Center>
    </Flex>
);

const ResizableHeader: React.FC<
    React.PropsWithChildren<ResizableHeaderProps>
> = ({
    headerGroups,
    isAllChecked,
    onAllChecked,
    checkedRows,
    isFixed,
    enableResize = true,
    sx,
    onSortCustomHandler,
    ...rest
}) => {
    const handleCheckboxKey = ({ keyCode }: any) => {
        if (keyCode === 32 || keyCode === 13) {
            if (onAllChecked) {
                onAllChecked();
            }
        }
    };

    const handleCheckboxClick = (e: any) => {
        if (onAllChecked) {
            onAllChecked();
        }
        e.preventDefault();
        e.stopPropagation();
    };

    const fixedStyles = isFixed
        ? { position: 'fixed', width: 'fill-available', zIndex: 1 }
        : {};

    return (
        <Thead
            as='div'
            sx={{ ...tableHeadStyles, ...sx, ...fixedStyles }}
            {...rest}
        >
            {headerGroups.map((headerGroup: any, i: number) => (
                <Tr
                    as='div'
                    {...headerGroup.getHeaderGroupProps()}
                    key={i}
                    sx={{
                        '> div:last-of-type': {
                            overflow: 'hidden',
                        },
                    }}
                >
                    {headerGroup.headers.map((column: any, index: number) => {
                        const isCheckCell =
                            checkedRows !== undefined && index === 0;
                        return (
                            <Th
                                as='div'
                                {...column.getHeaderProps(
                                    column.getSortByToggleProps(),
                                )}
                                data-testid={'column-header'}
                                key={column.id}
                                sx={{
                                    ...adjustBorderOnResizeStyles(
                                        column.isResizing,
                                        isCheckCell,
                                    ),
                                    ...(column.id === EXPANDO_COLUMN_ID && {
                                        pr: 0,
                                    }),
                                }}
                                {...(isCheckCell && {
                                    onClick: (e) => handleCheckboxClick(e),
                                    onKeyUp: (e) => handleCheckboxKey(e),
                                })}
                                {...(onSortCustomHandler && {
                                    onClick: (e) => {
                                        onSortCustomHandler(column);
                                        if (isCheckCell) {
                                            handleCheckboxClick(e);
                                        }
                                    },
                                })}
                            >
                                {isCheckCell ? (
                                    <Checkbox
                                        sx={checkboxStyles}
                                        aria-checked={false}
                                        tabIndex={-1}
                                        isChecked={isAllChecked}
                                        isIndeterminate={
                                            checkedRows &&
                                            checkedRows.length > 0 &&
                                            !isAllChecked
                                        }
                                        data-testid='column-header-check-all-checkbox'
                                    />
                                ) : (
                                    <span>{column.render('Header')}</span>
                                )}

                                {!isCheckCell && !column.disableSortBy && (
                                    <Sorter
                                        isActive={
                                            column.isSorted ||
                                            column.sortDirection ===
                                                SORT_DIRECTION.ASC ||
                                            column.sortDirection ===
                                                SORT_DIRECTION.DESC
                                        }
                                        isDescending={
                                            column.isSortedDesc ||
                                            column.sortDirection ===
                                                SORT_DIRECTION.DESC
                                        }
                                    />
                                )}
                                {!isCheckCell && (
                                    <Box
                                        as='div'
                                        {...(enableResize &&
                                            column.getResizerProps())}
                                        data-testid={'resizer-box'}
                                        sx={resizerStyles(column.isResizing)}
                                        // onclick here prevents client side sorting when resizing
                                        onClick={(e) => e.stopPropagation()}
                                    >
                                        <Resizer />
                                    </Box>
                                )}
                            </Th>
                        );
                    })}
                </Tr>
            ))}
        </Thead>
    );
};

export default ResizableHeader;
