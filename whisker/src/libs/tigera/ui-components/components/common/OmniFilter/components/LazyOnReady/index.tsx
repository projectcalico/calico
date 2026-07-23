import React from 'react';

const LazyOnReady: React.FC<{ onReady?: () => void }> = ({ onReady }) => {
    React.useEffect(() => onReady && onReady(), []);

    return null;
};

export default LazyOnReady;
