import { Table, TableProps, Tbody, Td, Th, Tr } from '@chakra-ui/react';
import React from 'react';
import { LogDocument } from '../..';

type LogDetailsTableProps = {
    logDocument: LogDocument;
    stringifyTableData: boolean;
} & TableProps;

const LogDetailsTable: React.FC<LogDetailsTableProps> = ({
    logDocument,
    stringifyTableData,
    ...rest
}) => {
    return (
        <Table {...rest}>
            <Tbody>
                {Object.entries(logDocument).map(([key, value]) => {
                    let info = value as string | React.ReactNode;

                    if (stringifyTableData) {
                        info = Array.isArray(value)
                            ? value.map((v) => JSON.stringify(v)).join(', ')
                            : JSON.stringify(value);
                    }

                    return (
                        <Tr key={key}>
                            <Th>{key}</Th>
                            <Td>{info}</Td>
                        </Tr>
                    );
                })}
            </Tbody>
        </Table>
    );
};

export default LogDetailsTable;
