export type OmniInternalListComponentProps = {
    options: OmniFilterOption[];
    selectedOptions: OmniFilterOption[];
    emptyMessage: string;
    showMoreButton: boolean;
    showSelectedList?: boolean;
    isLoadingMore: boolean;
    height?: number;
    labelShowMore?: string;
    labelListHeader?: string;
    labelSelectedListHeader?: string;
    onChange: (options: OmniFilterOption[]) => void;
    onRequestMore?: () => void;
};

export type OmniFilterOption = {
    label: string;
    value: string;
    data?: any;
};

// todo: may not be needed
export enum OperatorType {
    Equals = '=',
    NotEquals = '!=',
    In = 'in',
    NotIn = '!in',
    Exists = 'exists',
    NotExists = '!exist',
    Contains = 'contains',
    StartsWith = 'starts with',
    EndsWith = 'ends with',
}
