import { useAppConfigQuery } from '@/api';
import {
    useDidUpdate,
    useLocalStorage,
} from '@/libs/tigera/ui-components/hooks';
import { AppConfig } from '@/types/render';
import React from 'react';

export const AppConfigContext = React.createContext<AppConfig | undefined>(
    undefined,
);

export const useAppConfig = () => React.useContext(AppConfigContext);

const AppConfigProvider: React.FC<React.PropsWithChildren> = ({ children }) => {
    const { data } = useAppConfigQuery();
    const [storedConfig, setStoredConfig] = useLocalStorage(
        'whisker.config',
        data,
    );

    useDidUpdate(() => {
        setStoredConfig(data);
    }, [data]);

    return (
        <AppConfigContext.Provider value={data ?? storedConfig}>
            {children}
        </AppConfigContext.Provider>
    );
};

export default AppConfigProvider;
