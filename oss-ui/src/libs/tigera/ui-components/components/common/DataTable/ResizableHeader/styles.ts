export const tableHeadStyles = {
    overflowY: 'auto',
    overflowX: 'hidden',
};

export const resizingIconStyles = {
    w: 4,
    h: 4,
};

export const resizingContainerStyles = {
    color: 'tigeraBlueMedium',
    h: '100%',
};

export const resizerSeperatorStyles = {
    flex: '1',
    bg: 'tigeraBlueMedium',
    maxWidth: '2px',
};

export const resizingIconFlexStyles = {
    maxWidth: '5px',
    flex: '1',
};

export const resizerStyles = (isResizing: boolean) => ({
    display: 'inline-block',
    position: 'absolute',
    right: '-10px',
    top: 0,
    opacity: isResizing ? 1 : 0,
    height: '100%',
    zIndex: 9, // TODO when move over to chakra fully use appropriate token
    width: '15px',
});

export const adjustBorderOnResizeStyles = (
    isResizing: boolean,
    isCheckCell: boolean,
) => ({
    color: 'tigera-color-on-surface',
    display: 'flex',
    alignItems: 'center',
    userSelect: 'none',
    borderRight: isCheckCell ? 'none' : isResizing && 'none',
});

export const checkboxStyles = { mt: '2px', mb: 0 };
