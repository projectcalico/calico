import '@tanstack/react-query';
import { ApiError } from './api';

declare module '@tanstack/react-query' {
    interface Register {
        defaultError: ApiError;
    }
}
