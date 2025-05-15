import { Text } from '@chakra-ui/react';
import { fireEvent, renderWithRouter, screen } from '@/test-utils/helper';
import Tabs from '../index';

describe('<Tabs/>', () => {
    it('it renders', () => {
        const onTabSelectedMock = jest.fn();

        const { asFragment } = renderWithRouter(
            <Tabs
                tabs={[
                    {
                        title: 'One',
                        content: <Text>This is a tab component one</Text>,
                        href: 'some-link',
                    },
                    {
                        title: 'Two',
                        content: <Text>This is a tab component two</Text>,
                        id: 'someId',
                        href: undefined,
                    },
                    {
                        title: 'Three',
                        content: <Text>This is a tab component three</Text>,
                    },
                ]}
                onTabSelected={onTabSelectedMock}
                selectedTabId={2}
                isLazy
            />,
        );

        expect(asFragment()).toMatchSnapshot();

        fireEvent.click(screen.getAllByTestId('tabs-tab')[0]);

        expect(onTabSelectedMock).toHaveBeenCalled();
    });
});
