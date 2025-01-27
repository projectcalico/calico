import React from 'react';
import { JsonView, allExpanded, defaultStyles } from 'react-json-view-lite';
import 'react-json-view-lite/dist/index.css';
import './styles.css';

interface JsonPrettierProps {
    data: any;
    style?: Record<string, string>;
}
const JsonPrettier: React.FC<JsonPrettierProps> = ({ data, style }) => {
    const styles = {
        ...defaultStyles,
        container: 'containerStyles',
        label: 'labelStyles',
        stringValue: 'stringStyles',
        nullValue: 'valueStyles',
        numberValue: 'valueStyles',
        undefinedValue: 'valueStyles',
        ...style,
    };

    return (
        <JsonView data={data} shouldExpandNode={allExpanded} style={styles} />
    );
};

export default JsonPrettier;
