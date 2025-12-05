import { API_URL } from '../api';

export const createEventSource = (path: string) =>
    new EventSource(`${API_URL}/${path}`);

const DEFAULT_START_TIME = 1;
const MAX_START_TIME = 60;
export const parseStartTime = (startTime: string | undefined) => {
    const maybeNumber = Number(startTime);
    const parsed = isNaN(maybeNumber) ? DEFAULT_START_TIME : maybeNumber;

    return parsed > MAX_START_TIME ? DEFAULT_START_TIME : parsed;
};
