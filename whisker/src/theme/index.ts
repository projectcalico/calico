import { extendTheme, ThemeConfig } from '@chakra-ui/react';
import colors from './colors';
import global from './global';
import semanticTokens from './tokens';
import {
    Link,
    LogDetailsView,
    StatusIndicator,
    Table,
    Tabs,
    Tag,
    Alert,
    Button,
    OmniFilter,
    Menu,
    Popover,
    Checkbox,
    OmniFilterList,
    Badge,
    CheckboxLoadingSkeleton,
    CheckboxListLoadingSkeleton,
    ReorderableCheckList,
    Tooltip,
    Radio,
} from './components';
import SearchInput from '@/libs/tigera/ui-components/components/common/SearchInput/styles';
import experimentalColors from './experimental-tokens/palette';
import experimentalSemanticTokens from './experimental-tokens';
import Accordion from './components/Accordion';

const config: ThemeConfig = {
    initialColorMode: 'dark',
    useSystemColorMode: false,
};

const theme = extendTheme({
    config,
    colors: {
        ...colors,
        ...experimentalColors,
    },
    semanticTokens: {
        colors: {
            ...semanticTokens.colors,
            ...experimentalSemanticTokens,
        },
    },
    styles: {
        global: () => global,
    },
    components: {
        Accordion,
        Link,
        LogDetailsView,
        StatusIndicator,
        Table,
        Tabs,
        Tag,
        Alert,
        Button,
        OmniFilter,
        Menu,
        Popover,
        Checkbox,
        OmniFilterList,
        Badge,
        CheckboxLoadingSkeleton,
        CheckboxListLoadingSkeleton,
        ReorderableCheckList,
        Tooltip,
        SearchInput,
        Radio,
    },
    fontSizes: {
        xxs: '0.625rem',
    },
    sizes: {
        100: '25rem',
    },
});

export { theme };
