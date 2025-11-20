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
} from './components';
import SearchInput from '@/libs/tigera/ui-components/components/common/SearchInput/styles';

const config: ThemeConfig = {
    initialColorMode: 'dark',
    useSystemColorMode: false,
};

const theme = extendTheme({
    config,
    colors,
    semanticTokens,
    styles: {
        global: () => global,
    },
    components: {
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
    },
    fontSizes: {
        xxs: '0.625rem',
    },
    sizes: {
        100: '25rem',
    },
});

export { theme };
