import type { HTMLChakraProps, SystemStyleObject } from '@chakra-ui/react';
import { Box, TableProps, useMultiStyleConfig } from '@chakra-ui/react';
import React from 'react';
import JsonPrettier from '../JsonPrettier';
import Tabs from '../Tabs';
import LogDetailsTable from './components/LogDetailsTable';

export interface LogDocument {
    [name: string]:
        | string
        | number
        | boolean
        | object
        | React.Component
        | null
        | undefined;
}

interface LogDetailsViewProps extends HTMLChakraProps<'div'> {
    logDocument: LogDocument;
    tableTabTitle?: string;
    jsonTabTitle?: string;
    sx?: SystemStyleObject;
    tableStyles?: TableProps;
    showTableOnly?: boolean;
    stringifyTableData?: boolean;
}

const LogDetailsView: React.FC<LogDetailsViewProps> = ({
    logDocument,
    tableStyles,
    tableTabTitle = 'Table',
    jsonTabTitle = 'JSON',
    showTableOnly = false,
    stringifyTableData = true,
    ...rest
}) => {
    const logViewStyles = useMultiStyleConfig('LogDetailsView', rest);
    const Table = (
        <LogDetailsTable
            __css={logViewStyles.table}
            sx={{ ...tableStyles }}
            logDocument={logDocument}
            stringifyTableData={stringifyTableData}
        />
    );

    return (
        <>
            {showTableOnly ? (
                Table
            ) : (
                <Box __css={logViewStyles.root} {...rest}>
                    <Tabs
                        onTabSelected={() => {}}
                        tabs={[
                            {
                                content: Table,
                                title: tableTabTitle,
                            },

                            {
                                content: <JsonPrettier data={logDocument} />,
                                title: jsonTabTitle,
                            },
                        ]}
                    />
                </Box>
            )}
        </>
    );
};

export default LogDetailsView;
