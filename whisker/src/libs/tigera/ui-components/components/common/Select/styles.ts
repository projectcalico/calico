import { ChakraStylesConfig } from 'chakra-react-select';

export default {
    control: (provided: any) => ({
        ...provided,
        height: '42px',
        boxShadow: 'none',
        '&[data-invalid="true"]': { boxShadow: 'none' },
        fontSize: 'sm',
    }),
    container: (provided: any) => ({
        ...provided,
        width: 'full',
    }),

    clearIndicator: (provided: any) => ({
        ...provided,
        fontSize: '0.60rem',
        color: 'tigeraGrey.700',
        '--close-button-size': '10px',
        ':hover': {
            bg: 'unset',
            color: 'tigeraGrey.900',
        },
    }),
    indicatorsContainer: (provided: any) => ({
        ...provided,
        fontSize: 'xl',
    }),
    multiValueRemove: (provided: any) => ({
        ...provided,
        fontSize: 'sm',
    }),
    menu: (provided: any) => ({
        ...provided,
        mt: 1,
        boxShadow: '0px 0px 8px #dcdde0 !important',
        borderColor: 'tigeraGrey.300',
        borderRadius: 'md',
        _dark: {
            boxShadow: 'none !important',
        },
    }),
    menuList: (provided: any) => ({
        ...provided,
        pt: 0,
        pb: 0,
        _dark: {
            boxShadow: 'none',
            border: 'none',
        },
    }),
    noOptionsMessage: (state: any) => ({
        ...state,
        textAlign: 'left',
        px: 4,
    }),
    option: (state: any) => ({
        ...state,
        fontWeight: 400,
        px: 2.5,
        py: 2,
        fontSize: 'sm',
        minWidth: 'fit-content',
        ':hover': {
            bg: 'tigeraGrey.200',
            color: 'tigeraBlack',
        },

        _dark: {
            background: 'tigeraGreyDark.200',
            _hover: {
                bg: 'tigeraGrey.800',
                color: 'tigeraWhite',
            },
            _selected: {
                background: 'tigeraBlueMediumDark',
                color: 'tigeraBlueMedium40',
            },
        },
    }),
    dropdownIndicator: (provided: any) => ({
        ...provided,
        bg: 'transparent',
        fontSize: 'xl',
        px: 2,
        cursor: 'inherit',
    }),
    indicatorSeparator: (provided: any) => ({
        ...provided,
        display: 'none',
    }),
    singleValue: (provided: any) => ({
        ...provided,
    }),
    multiValue: (provided: any) => ({
        ...provided,
        py: 4,
        borderRadius: 0,
        borderWidth: 0,
        bg: '#ebf5ff', // TODO THIS COLOR IS NOT IN THE DESIGN THEME! NEEDS FEEDBACK FROM DESIGNERS
        svg: {
            color: 'white',
        },
        p: 0,
        pr: 1,
        fontSize: 'xs',
        lineHeight: 5,
        height: 6,
        '>span': {
            py: 3,
            px: '5px',
        },
        '>div': {
            bg: 'tigeraBlueDark',
            opacity: 1,
            borderRadius: 0,
            height: 6,
            width: 6,
        },
    }),
} satisfies ChakraStylesConfig;
