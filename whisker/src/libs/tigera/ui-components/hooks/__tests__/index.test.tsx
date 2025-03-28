import { render } from '@/test-utils/helper';
import { useDidUpdate } from '..';

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
