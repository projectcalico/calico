import {
    Tag as ChakraTag,
    TagCloseButton,
    TagProps as ChakraTagProps,
} from '@chakra-ui/react';

type Tag = {
    value: string;
    label: string;
};
export type TagProps = ChakraTagProps & {
    tag: Tag;
    onRemove: (option: Tag) => void;
};

const Tag: React.FC<TagProps> = ({ tag, onRemove, ...rest }) => (
    <ChakraTag variant='solid' cursor='default' {...rest}>
        {tag.label}
        <TagCloseButton
            data-testid='tag-close-button'
            onClick={(event) => {
                event.stopPropagation();
                onRemove(tag);
            }}
        />
    </ChakraTag>
);

export default Tag;
