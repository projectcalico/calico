export type PolicyFilterKey = 'kind' | 'tier' | 'namespace' | 'name';

export type PolicyFilter = Partial<Record<PolicyFilterKey, string>>;
