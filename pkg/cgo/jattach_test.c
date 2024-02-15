#include "jattach.c"

int main(int argc,char ** argv){
    OutputInfo outputInfo;
    int result=jattach(&outputInfo,atoi(argv[1]),argv[2],"",1);
    return result;
}