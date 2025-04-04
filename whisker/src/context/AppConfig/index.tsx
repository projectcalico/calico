import { useAppConfigQuery } from '@/api';
import { AppConfig } from '@/types/render';
import React from 'react';

export const AppConfigContext = React.createContext<AppConfig | undefined>(
    undefined,
);

export const useAppConfig = () => React.useContext(AppConfigContext);

const AppConfigProvider: React.FC<React.PropsWithChildren> = ({ children }) => {
    const { data } = useAppConfigQuery();

    return (
        <AppConfigContext.Provider value={data}>
            {children}
        </AppConfigContext.Provider>
    );
};

export default AppConfigProvider;
