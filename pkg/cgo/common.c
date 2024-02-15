#include <stdio.h>
#include <stdlib.h>
#include "common.h"

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
void output(struct OutputQueue *queue,OutputInfo *result){
    result->size= queue->allSize;
    char *byteArray = (char*)malloc(result->size * sizeof(char));
    result->output=byteArray;
    struct OutputNode *node=queue->firstNode;
    while(node!=NULL){
        memcpy(byteArray, node->buffer, node->size);
        byteArray+=node->size;
        node=node->next;
    }
}

void freeQueue(struct OutputQueue *queue){
    struct OutputNode *node=queue->firstNode;
    while(node!=NULL){
        struct OutputNode *waitToFreeNode=node;
        node=node->next;
        free(waitToFreeNode);
    }
    free(queue);
}