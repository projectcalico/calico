import React from 'react';

type Action = { type: 'show' | 'hide' };
type Dispatch = (action: Action) => void;
type State = { isVisible: boolean };

export const PromoBannerContext = React.createContext<
    { state: State; dispatch: Dispatch } | undefined
>(undefined);

const reducer = (_state: State, action: Action) => {
    switch (action.type) {
        case 'show': {
            return { isVisible: true };
        }
        case 'hide': {
            return { isVisible: false };
        }
    }
};

export const usePromoBanner = () => {
    const context = React.useContext(PromoBannerContext);

    // Avoid undefined check in components
    if (context === undefined) {
        throw new Error('Context error');
    }

    return context;
};

const PromoBannerProvider: React.FC<React.PropsWithChildren> = ({
    children,
}) => {
    const [state, dispatch] = React.useReducer(reducer, { isVisible: false });
    const value = { state, dispatch };
    return (
        <PromoBannerContext.Provider value={value}>
            {children}
        </PromoBannerContext.Provider>
    );
};

export default PromoBannerProvider;
