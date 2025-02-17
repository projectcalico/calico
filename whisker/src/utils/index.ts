import { API_URL } from '../api';

export const createEventSource = (path: string) =>
    new EventSource(`${API_URL}/${path}`);
