import '@testing-library/jest-dom';
import { enableFetchMocks } from 'jest-fetch-mock';
import { TextDecoder, TextEncoder } from 'util';

Object.assign(global, { TextDecoder, TextEncoder });

enableFetchMocks();
