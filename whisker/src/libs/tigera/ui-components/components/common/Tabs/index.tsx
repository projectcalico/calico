import * as React from 'react';
import {
    Tabs as ChakraTabs,
    TabList,
    Tab as ChakraTab,
    TabPanels,
    TabPanel,
    useStyleConfig,
    SystemStyleObject,
} from '@chakra-ui/react';
import { Tab } from './types';
import Link from '../Link';

interface TabsProps {
    tabs: Tab[];
    selectedTabId?: number;
    onTabSelected?: (id: number) => void;
    isLazy?: boolean;
    sx?: SystemStyleObject;
}

const Tabs: React.FC<React.PropsWithChildren<TabsProps>> = ({
    tabs,
    onTabSelected,
    selectedTabId,
    ...rest
}) => {
    const tabsStyles = useStyleConfig('Tabs', rest);

    const renderTab = (tab: Tab, index: any) => (
        <ChakraTab
            data-testid={tab.dataTestId ? `${tab.dataTestId}-tab` : 'tabs-tab'}
            isDisabled={tab.disabled}
            key={index}
            id={tab.href}
        >
            {tab.title}
        </ChakraTab>
    );

    return (
        <ChakraTabs
            __css={tabsStyles}
            defaultIndex={selectedTabId}
            index={selectedTabId}
            onChange={(index) => onTabSelected && onTabSelected(index)}
            {...rest}
        >
            <TabList>
                {tabs.map((tab, index) =>
                    tab.href ? (
                        <Link to={tab.href} key={index}>
                            {renderTab(tab, index)}
                        </Link>
                    ) : (
                        renderTab(tab, index)
                    ),
                )}
            </TabList>

            <TabPanels>
                {tabs.map((tab, index) => (
                    <TabPanel
                        key={index}
                        id={tab.href}
                        data-testid={
                            tab.dataTestId
                                ? `${tab.dataTestId}-tab-panel`
                                : 'tabs-tab-panel'
                        }
                        sx={tab.sx}
                    >
                        {tab.content}
                    </TabPanel>
                ))}
            </TabPanels>
        </ChakraTabs>
    );
};

export default Tabs;
