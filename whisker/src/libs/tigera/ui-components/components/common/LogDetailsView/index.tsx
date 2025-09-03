import type { HTMLChakraProps, SystemStyleObject } from '@chakra-ui/react';
import { Box, TableProps, useMultiStyleConfig } from '@chakra-ui/react';
import React from 'react';
import JsonPrettier from '../JsonPrettier';
import Tabs from '../Tabs';
import LogDetailsTable, {
    CustomTableDataVisualiser,
} from './components/LogDetailsTable';

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
    jsonData?: LogDocument;
    tableTabTitle?: string;
    jsonTabTitle?: string;
    sx?: SystemStyleObject;
    tableStyles?: TableProps;
    jsonTabStyles?: SystemStyleObject;
    showTableOnly?: boolean;
    stringifyTableData?: boolean;
    defaultExpandedJsonNodes?: number;
    size?: string;
    customTableDataVisualisers?: Array<CustomTableDataVisualiser>;
}

const LogDetailsView: React.FC<LogDetailsViewProps> = ({
    logDocument,
    jsonData,
    tableStyles,
    jsonTabStyles,
    tableTabTitle = 'Table',
    jsonTabTitle = 'JSON',
    showTableOnly = false,
    stringifyTableData = true,
    defaultExpandedJsonNodes,
    customTableDataVisualisers,
    ...rest
}) => {
    const logViewStyles = useMultiStyleConfig('LogDetailsView', rest);
    const { size } = rest;

    const Table = (
        <LogDetailsTable
            __css={logViewStyles.table}
            sx={tableStyles}
            size={size}
            logDocument={logDocument}
            stringifyTableData={stringifyTableData}
            customTableDataVisualisers={customTableDataVisualisers}
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
                                content: (
                                    <JsonPrettier
                                        data={jsonData ?? logDocument}
                                        defaultExpandedNodes={
                                            defaultExpandedJsonNodes
                                        }
                                    />
                                ),
                                title: jsonTabTitle,
                                sx: jsonTabStyles,
                            },
                        ]}
                        size={size}
                    />
                </Box>
            )}
        </>
    );
};

export default LogDetailsView;
