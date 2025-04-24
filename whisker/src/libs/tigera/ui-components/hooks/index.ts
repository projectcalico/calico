import React from 'react';

export const useDidUpdate = (callback: () => void, deps: Array<any>) => {
    const hasMount = React.useRef(false);
    React.useEffect(() => {
        if (hasMount.current) {
            callback();
        } else {
            hasMount.current = true;
        }
    }, deps);
};

export const useLocalStorage = <T>(key: string, initialValue: T) => {
    const [storedValue, setStoredValue] = React.useState<T>(() => {
        try {
            const item = window.localStorage.getItem(key);

            return item ? JSON.parse(item) : initialValue;
        } catch (_error) {
            return initialValue;
        }
    });

    const setValue = (value: T | ((val: T) => T)) => {
        try {
            const valueToStore =
                value instanceof Function ? value(storedValue) : value;

            if (valueToStore === undefined) {
                window.localStorage.removeItem(key);
            } else {
                window.localStorage.setItem(key, JSON.stringify(valueToStore));
            }

            setStoredValue(valueToStore);
        } catch (error) {
            console.error(error);
        }
    };

    return [storedValue, setValue] as const;
};
