import { render, screen } from '@/test-utils/helper';
import { useDidUpdate, useLocalStorage } from '..';
import React from 'react';

describe('useDidUpdate', () => {
    const TestUseDidUpdateHook = ({
        mockUpdateCallback,
        mockParamChangeProp,
    }: any) => {
        useDidUpdate(mockUpdateCallback, [mockParamChangeProp]);
        return null;
    };

    it('executes useDidUpdate correctly', () => {
        const mockUpdateCallback = jest.fn();

        const { rerender } = render(
            <TestUseDidUpdateHook
                mockUpdateCallback={mockUpdateCallback}
                mockParamChangeProp={false}
            />,
        );
        expect(mockUpdateCallback).toHaveBeenCalledTimes(0);

        rerender(
            <TestUseDidUpdateHook
                mockUpdateCallback={mockUpdateCallback}
                mockParamChangeProp={true}
            />,
        );

        expect(mockUpdateCallback).toHaveBeenCalledTimes(1);
    });
});

describe('useLocalStorage', () => {
    const TestUseLocalStorageHook = ({ key, defaultResult }: any) => {
        const result = useLocalStorage(key, defaultResult);
        return <div>result: {result}</div>;
    };

    const TestUseLocalStorageSetOnMountHook = ({
        key,
        defaultResult,
        setValue,
    }: any) => {
        const [result, setResult] = useLocalStorage(key, defaultResult);
        React.useEffect(() => {
            setResult(setValue);
        }, [setValue]);
        return <div>result: {result}</div>;
    };

    it('executes useLocalStorage to read invalid data structure', () => {
        render(
            <TestUseLocalStorageHook
                key={'test'}
                defaultResult={'result: mockDefaultResult'}
            />,
        );

        expect(screen.getByText(/result: /)).toBeInTheDocument();
        expect(
            screen.getByText(/result: mockDefaultResult/),
        ).toBeInTheDocument();
    });

    it('executes useLocalStorage to set invalid data structure', () => {
        const cyclicalObj = { a: undefined };
        cyclicalObj.a = { b: cyclicalObj } as any;

        render(
            <TestUseLocalStorageSetOnMountHook
                key={'test'}
                defaultResult={'result: mockDefaultResult'}
                setValue={cyclicalObj}
            />,
        );

        expect(screen.getByText(/result: /)).toBeInTheDocument();
        expect(
            screen.getByText(/result: mockDefaultResult/),
        ).toBeInTheDocument();
    });
});
