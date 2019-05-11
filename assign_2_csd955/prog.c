#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

int main(void) {
    
    char str[] = "Test string 1\n";
    char str1[] = "Test string 2\n";
   
    printf("\nCalling the fopen() function...\n");

    FILE *fd = fopen("./docs/test.txt","r");
    
    if (!fd) {
        printf("fopen() returned NULL\n");
        exit(1);
    }
    
    printf("\nfopen() succeeded\n");
    fclose(fd);
    
    fd = fopen("./docs/testappend.txt","a+");

    printf("\nCalling the fwrite() function...\n");
    
    fwrite(str , 1 , sizeof(str) , fd ); 
    
    fclose(fd);
    
    fd = fopen("./docs/testappend.txt","a+");
    
    fwrite(str1 , 1 , sizeof(str1) , fd ); 
    
    printf("\nfwrite() succeeded\n");
    
    fclose(fd);    
    
    printf("\nCalling the open() function...\n");
    
    int filedesc = open("./docs/testappend.txt", O_RDWR); 
    
    if (filedesc == -1){
        printf("open() returned -1\n");
        exit(1);
    }
    printf("\nopen() succeeded\n");
    
    printf("\nCalling the open() function...\n");
    
    int fdopen = open("./docs/testopen.txt", O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
    
    if (fdopen == -1){
        printf("open() returned -1\n");
        exit(1);
    }
    printf("\nopen() succeeded\n");
    
    close(fdopen);
    close(filedesc);
    
    return 0;
}
