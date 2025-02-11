export default {
    testEnvironment: 'jsdom',
    transform: {
        '^.+\\.(t|j)sx?$': [
            '@swc/jest',
            {
                jsc: {
                    transform: {
                        react: {
                            runtime: 'automatic',
                        },
                    },
                },
            },
        ],
    },
    setupFilesAfterEnv: ['<rootDir>/jest.setup.ts'],
    moduleNameMapper: {
        '^.+\\.svg$': 'jest-transformer-svg',
        '.+\\.(css|less|sass|scss)$':
            '<rootDir>/test-utils/__mocks__/styleMock.js',
        '^@/test-utils/(.*)$': '<rootDir>/test-utils/$1',
        '^@/(.*)$': '<rootDir>/src/$1',
    },
    coverageThreshold: {
        global: {
            branches: 85,
            functions: 85,
            lines: 90,
            statements: 90,
        },
    },
    coveragePathIgnorePatterns: ['<rootDir>/src/theme', '<rootDir>/src/libs'],
};
