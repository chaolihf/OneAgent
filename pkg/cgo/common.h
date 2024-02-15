#define MAX_PATH 1024
#include <string.h>

#ifndef COMMON_HEAD
#define COMMON_HEAD
    /**
     * 定义返回结果
    */
    typedef struct OutputInfo{
        int result;
        int size;
        char* output;
    } OutputInfo;


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

    struct OutputQueue* initOutputQueue();

    void addOutputNode(struct OutputQueue *queue,int size,char* buffer);

    void output(struct OutputQueue *queue,OutputInfo *result);

    void freeQueue(struct OutputQueue *queue);

#endif