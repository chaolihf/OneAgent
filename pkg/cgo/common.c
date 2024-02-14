#include <stdio.h>
#include <stdlib.h>

/**
 * 定义一个缓存字符数组长度和指针的节点
*/
struct OutputNode {
    int size;
    char* buffer;
    struct OutputNode* next;
}  ;

/**
 * 通过一个队列来缓存所有的字符数组，这样在最后可以拼接起来复制成一个字符数组
*/
struct OutputQueue {
    struct OutputNode* firstNode;
    struct OutputNode* endNode;
    int allSize;
};

struct OutputQueue* initOutputQueue(){
    struct OutputQueue *queue=malloc(sizeof(struct OutputQueue));
    queue->firstNode=NULL;
    queue->endNode=NULL;
    queue->allSize=0;
    return queue;
}

/**
 * 增加一个待输出结点
*/
void addOutputNode(struct OutputQueue *queue,int size,char* buffer){
    struct OutputNode* newNode=malloc(sizeof(struct OutputNode));
    newNode->buffer=buffer;
    newNode->size=size;
    queue->allSize+=size;
    if(queue->firstNode==NULL){
        queue->firstNode=newNode;
        queue->endNode=newNode;
    } else {
        queue->endNode->next=newNode;
        queue->endNode=newNode;
    }
}

/**
 * 输出所有的数组
*/
void output(struct OutputQueue *queue,unsigned char** byteArray, size_t* length){
    *length = queue->allSize;
    *byteArray = (unsigned char*)malloc(*length * sizeof(unsigned char));
    char result[queue->allSize];
    struct OutputNode *node=queue->firstNode;
    int offset=0;
    while(node!=NULL){
        memcpy(&result[offset], node->buffer, node->size);
        offset+=node->size;
        node=node->next;
    }
}