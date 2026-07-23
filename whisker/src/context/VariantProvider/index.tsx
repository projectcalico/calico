import React from 'react';

export const VariantContext = React.createContext<string>('default');

export const useVariant = <T extends string = string>(): T =>
    React.useContext(VariantContext) as T;

type VariantProviderProps = {
    children: React.ReactNode;
    variant?: string;
};

const VariantProvider: React.FC<VariantProviderProps> = ({
    children,
    variant = 'default',
}) => {
    return (
        <VariantContext.Provider value={variant}>
            {children}
        </VariantContext.Provider>
    );
};

export default VariantProvider;
