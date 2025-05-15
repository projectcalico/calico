import React from 'react';
import {
    JsonView,
    allExpanded,
    defaultStyles,
    darkStyles,
} from 'react-json-view-lite';
import 'react-json-view-lite/dist/index.css';
import './styles.css';
import { useColorModeValue } from '@chakra-ui/react';

interface JsonPrettierProps {
    data: any;
    style?: Record<string, string>;
    defaultExpandedNodes?: number;
}

const lightSx = {
    ...defaultStyles,
    container: 'containerStyles',
    label: 'labelStyles',
    stringValue: 'stringStyles',
    nullValue: 'valueStyles',
    numberValue: 'valueStyles',
    undefinedValue: 'valueStyles',
};

const darkSx = {
    ...darkStyles,
    container: 'containerStylesDark',
    label: 'labelStylesDark',
    stringValue: 'stringStylesDark',
    nullValue: 'valueStylesDark',
    numberValue: 'valueStylesDark',
    undefinedValue: 'valueStylesDark',
};

const JsonPrettier: React.FC<JsonPrettierProps> = ({
    data,
    style,
    defaultExpandedNodes,
}) => {
    const css = useColorModeValue(lightSx, darkSx);
    const styles = {
        ...css,
        ...style,
    };

    return (
        <JsonView
            data={data}
            shouldExpandNode={
                defaultExpandedNodes
                    ? (node) => node <= defaultExpandedNodes
                    : allExpanded
            }
            style={styles}
        />
    );
};

export default JsonPrettier;
