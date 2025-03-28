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
