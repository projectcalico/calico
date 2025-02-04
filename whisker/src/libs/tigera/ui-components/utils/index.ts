export type QueryObject = Record<
    string,
    string | number | boolean | string[] | null | undefined
>;

export const objToQueryStr = (queryObject: QueryObject) => {
    try {
        const queries: string[] = [];

        for (const key in queryObject) {
            const value = queryObject[key];

            if (value === null || value === undefined) {
                continue;
            }

            if (Array.isArray(value)) {
                value.forEach((item) => queries.push(`${key}=${item}`));
            } else {
                queries.push(`${key}=${value}`);
            }
        }

        if (queries.length) {
            return `?${queries.join('&')}`;
        } else {
            throw new Error(
                'Value supplied to objToQueryStr function is invalid',
            );
        }
    } catch (err) {
        console.error(err);
        return '';
    }
};
