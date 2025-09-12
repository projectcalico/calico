import React from 'react';
import { Table, TableProps, Tbody, Td, Th, Tr } from '@chakra-ui/react';
import { LogDocument } from '../..';

export type CustomTableDataVisualiser<TProps = any> = {
    key: string;
    component: React.ComponentType<TProps>;
};

type LogDetailsTableProps = {
    logDocument: LogDocument;
    stringifyTableData: boolean;
    customTableDataVisualisers?: Array<CustomTableDataVisualiser>;
} & TableProps;

const LogDetailsTable: React.FC<LogDetailsTableProps> = ({
    logDocument,
    stringifyTableData,
    customTableDataVisualisers,
    ...rest
}) => {
    return (
        <Table {...rest}>
            <Tbody>
                {Object.entries(logDocument).map(([key, value]) => {
                    let info = value as string | React.ReactNode;
                    let infoJSON;

                    if (stringifyTableData) {
                        info = Array.isArray(value)
                            ? value.map((v) => JSON.stringify(v)).join(', ')
                            : JSON.stringify(value);
                    }

                    const CustomDataVisualiser =
                        customTableDataVisualisers?.find(
                            (tableDataCustom) => tableDataCustom.key === key,
                        )?.component;

                    if (CustomDataVisualiser) {
                        try {
                            infoJSON = JSON.parse(info as string);
                        } catch (e) {
                            console.error(
                                'Failed to parse expected JSON from flow logs stream',
                                e,
                            );
                        }
                    }

                    return (
                        <Tr key={key}>
                            <Th>{key}</Th>
                            <Td>
                                {CustomDataVisualiser && infoJSON ? (
                                    <CustomDataVisualiser
                                        tableCellData={infoJSON}
                                    />
                                ) : (
                                    info
                                )}
                            </Td>
                        </Tr>
                    );
                })}
            </Tbody>
        </Table>
    );
};

export default LogDetailsTable;
