#include "jattach.c"

int main(int argc,char ** argv){
    size_t length;
    char  source[81920] ;
    jattach(&source,&length,atoi(argv[1]),argv[2],"",1);
    return 0;
}