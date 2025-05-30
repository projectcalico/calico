import React from 'react';
import {
    Modal,
    ModalOverlay,
    ModalContent,
    ModalFooter,
    ModalHeader,
    ModalBody,
    Checkbox,
    Box,
    Flex,
    Icon,
    Button,
    List,
    ListItem,
    useMultiStyleConfig,
} from '@chakra-ui/react';
import {
    DragDropContext,
    Droppable,
    Draggable,
    DraggableLocation,
} from '@hello-pangea/dnd';
import { DndIcon } from '@/icons';
import { cloneDeep } from 'lodash';

export type ReorderableList<T> = T & {
    checked: boolean;
};

interface ReorderableCheckListProps<T> {
    onSave: (columns: Array<ReorderableList<T>>) => void;
    onClose: () => void;
    title: string;
    items: Array<ReorderableList<T>>;
    keyProp: string;
    labelProp: string;
    isOpen: boolean;
    size: string;
}

const ReorderableCheckList = <T,>({
    isOpen,
    onClose,
    onSave,
    title,
    items = [],
    keyProp = 'id',
    labelProp = 'id',
    ...rest
}: ReorderableCheckListProps<T>) => {
    const [list, setList] = React.useState(cloneDeep(items));

    const styles = useMultiStyleConfig('ReorderableCheckList', rest);

    const onDragEnd = (result: {
        source: DraggableLocation;
        destination: DraggableLocation | null;
    }) => {
        if (!result.destination) return; // If dropped outside the list, do nothing

        const updatedItems = [...list];
        const [movedItem] = updatedItems.splice(result.source.index, 1);
        updatedItems.splice(result.destination.index, 0, movedItem);

        setList(updatedItems);
    };

    const onCheckboxChange = (checked: boolean, index: number) => {
        const listCopy = [...list];
        listCopy[index].checked = checked;
        setList(listCopy);
    };

    return (
        <Modal
            closeOnOverlayClick={false}
            isOpen={isOpen}
            onClose={onClose}
            {...rest}
        >
            <ModalOverlay />

            <ModalContent sx={styles.root}>
                <ModalHeader sx={styles.header}>{title}</ModalHeader>
                <ModalBody
                    data-testid='reorderable-checklist-modal-body'
                    sx={styles.body}
                >
                    <DragDropContext onDragEnd={onDragEnd}>
                        <Droppable droppableId='droppable'>
                            {(provided) => (
                                <Box
                                    {...provided.droppableProps}
                                    ref={provided.innerRef}
                                >
                                    <List sx={styles.list}>
                                        {list.map((item, index) => {
                                            const keyValue = String(
                                                item[
                                                    keyProp as keyof typeof item
                                                ],
                                            );
                                            const labelvalue = String(
                                                item[
                                                    labelProp as keyof typeof item
                                                ],
                                            );
                                            return (
                                                <Draggable
                                                    key={keyValue}
                                                    draggableId={keyValue}
                                                    index={index}
                                                >
                                                    {(provided, snapshot) => (
                                                        <ListItem
                                                            sx={{
                                                                ...styles.item,
                                                                ...provided
                                                                    .draggableProps
                                                                    .style,
                                                            }}
                                                            key={keyValue}
                                                            ref={
                                                                provided.innerRef
                                                            }
                                                            {...provided.draggableProps}
                                                            {...provided.dragHandleProps}
                                                            boxShadow={
                                                                snapshot.isDragging
                                                                    ? 'xl'
                                                                    : 'none'
                                                            }
                                                        >
                                                            <Flex
                                                                alignItems={
                                                                    'center'
                                                                }
                                                                justifyContent={
                                                                    'space-between'
                                                                }
                                                            >
                                                                <Checkbox
                                                                    sx={
                                                                        styles.checkbox
                                                                    }
                                                                    key={
                                                                        keyValue
                                                                    }
                                                                    isChecked={
                                                                        item.checked
                                                                    }
                                                                    onChange={(
                                                                        event,
                                                                    ) => {
                                                                        onCheckboxChange(
                                                                            event
                                                                                .target
                                                                                .checked,
                                                                            index,
                                                                        );
                                                                    }}
                                                                    data-testid={`${keyValue}-checkbox`}
                                                                >
                                                                    {labelvalue}
                                                                </Checkbox>
                                                                <Icon
                                                                    as={DndIcon}
                                                                    data-testid={`${keyValue}-draghandle`}
                                                                />
                                                            </Flex>
                                                        </ListItem>
                                                    )}
                                                </Draggable>
                                            );
                                        })}
                                        {provided.placeholder}
                                    </List>
                                </Box>
                            )}
                        </Droppable>
                    </DragDropContext>
                </ModalBody>
                <ModalFooter sx={styles.footer}>
                    <Button
                        onClick={onClose}
                        variant={'outline'}
                        mr={4}
                        sx={styles.footerButton}
                    >
                        Cancel
                    </Button>
                    <Button
                        onClick={() => {
                            onSave(list);
                            onClose();
                        }}
                        sx={styles.footerButton}
                    >
                        Save
                    </Button>
                </ModalFooter>
            </ModalContent>
        </Modal>
    );
};

export default ReorderableCheckList;
