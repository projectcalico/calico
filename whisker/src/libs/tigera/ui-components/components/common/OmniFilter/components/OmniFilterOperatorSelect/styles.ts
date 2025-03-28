export const selectStyles = {
    control: (provided: any) => ({
        ...provided,
        maxHeight: '32px',
        backgroundColor: 'tigeraGrey.100',
        _hover: {
            backgroundColor: 'tigeraGrey.200',
        },
        _focusVisible: {
            backgroundColor: 'tigeraGrey.100',
            _hover: {
                backgroundColor: 'tigeraGrey.200',
            },
        },
    }),
};
