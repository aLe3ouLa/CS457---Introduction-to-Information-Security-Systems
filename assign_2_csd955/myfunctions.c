#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include <openssl/md5.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>

#define PATH_MAX 1024

#define STR_VALUE(val) #val
#define STR(name) STR_VALUE(name)

#define PATH_LEN 256
#define MD5_LEN 32

void makeHash (unsigned char *, unsigned char *, size_t);
void writeInLog(char *, const char *, char *, char *, char *, char *,  unsigned char *);
void SpyUserActivity(int, const char *, char *, char *);
FILE *fopen(const char *, const char *);



void makeHash (unsigned char *hash, unsigned char *data, size_t len){
    int i;
    for (i = 0; i < len; i++){
        sprintf((char * restrict)&(hash[i*2]),"%02x",  data[i]);
    }
}



void writeInLog(char * userID, const char *filename, char *date, char *time, char *open, char *action_denied,  unsigned char *hash){
    char result[1024];

    size_t (*original_open)(const char *, int, mode_t);
    original_open = dlsym(RTLD_NEXT, "open");
    /* As the exercise stated the log must have append mode and only owner can read and write in it*/
    size_t fileDescr = (*original_open)("./docs/mylog.txt", O_APPEND | O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);

    
    printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\n",userID,filename,date,time,open,action_denied,hash);
    
    sprintf(result,  "%s %s %s %s %s %s %s\n",userID,filename,date,time,open,action_denied,hash);
    
    
    size_t (*original_write)(int, const void *, size_t);
    original_write = dlsym(RTLD_NEXT, "write");
    (*original_write)(fileDescr, &result, strlen(result));
    
    close(fileDescr);
}

void SpyUserActivity(int filedescr, const char *path, char * open, char * action_denied){
    
    char currentdate[11];
    char currenttime[9];
    time_t t = time(NULL);
    struct tm * tm_info = localtime(&t);
    char userID[5];
    unsigned char c[MD5_DIGEST_LENGTH];
    MD5_CTX mdContext;
    int bytes;
    unsigned char *data;
    unsigned char *hash = NULL;
    
    /*Get system user*/
    uid_t uid = getuid();
    sprintf(userID, "%d", uid);
    
    /* Get system time */
    strftime(currentdate, 11, "%Y-%m-%d", tm_info);
    strftime(currenttime, 9, "%H:%M:%S", tm_info);
    
    /* Get hash */
    data = malloc(256);
    
    if (filedescr != -1){
        /*File is opened.
         * if the right permissions correspond to descriptor, the hash will be produced 
         * else the action_denied become zero and hash is null (because we can't read the file)  */
        MD5_Init(&mdContext);
        bytes = read(filedescr, data, 256);
        if (bytes > 0){
            /*regular file*/
            while(bytes > 0){
                MD5_Update(&mdContext, data, bytes);
                bytes = read(filedescr, data, 256);
            }
                
            MD5_Final(c, &mdContext);
                
            hash = malloc(MD5_DIGEST_LENGTH * 2);
            makeHash(hash, c, MD5_DIGEST_LENGTH);
                
        }else if(bytes == 0){
            /* empty file */
            MD5_Update(&mdContext, data, bytes);
            MD5_Final(c, &mdContext);
                
            hash = malloc(MD5_DIGEST_LENGTH * 2);
            makeHash(hash, c, MD5_DIGEST_LENGTH);
        }else{
            /* can't read the file */
            hash = NULL;
        }
    }else{
        /* File descriptor == -1, we don't have access to file to produce hash value. */
        hash = NULL;
        action_denied = NULL;
        action_denied = malloc(sizeof(char));
        strcpy(action_denied, "1");
    }
    
    writeInLog(userID, path, currentdate, currenttime, open ,action_denied, hash);
    free(data);
}


FILE *fopen(const char *path, const char *mode) {
    int actiondenied = 0; 
    errno = 0;
    printf("In our own fopen, opening %s\n", path);
    
    FILE *(*original_fopen)(const char*, const char*);
    original_fopen = dlsym(RTLD_NEXT, "fopen");
    FILE * myfile = (*original_fopen)(path, mode);
    
    if (myfile == NULL){
        printf("errno: %d\n", errno);
        if (errno == EACCES || errno == EPERM){
           fprintf(stdout,"Not having permissions to fopen the file.\n");
            actiondenied = 1;
        }else if (errno == ENOENT){
            fprintf(stdout,"The file you trying to open doesn't exist.\n");
            return myfile;
        }else{
            fprintf(stdout,"Unknown error, not permission related!\n");
            return myfile;
        }
    }
    
    int fno = fileno(myfile); 
    SpyUserActivity(fno, path, "1", (actiondenied == 1)? "1":"0");
        
    return myfile;
}

int open(const char *path, int oflags,...){
    int actiondenied = 0; 
    va_list arg;
    int fileDescr;
    mode_t mode = -1;
    
    printf("In our own open, opening %s\n", path);
    
    
    if (!(oflags & O_CREAT)){
        size_t (*original_open)(const char *, int);
        original_open = dlsym(RTLD_NEXT, "open");
        fileDescr = (*original_open)(path, oflags);
    }else{
        va_start(arg, oflags);
        mode = va_arg(arg, int);
        va_end(arg);
        va_start (arg, oflags);
        mode = va_arg(arg, mode_t);
        va_end(arg);
        size_t (*original_open)(const char *, int, mode_t);
        original_open = dlsym(RTLD_NEXT, "open");
        fileDescr = (*original_open)(path, oflags,mode);
    }
    
    
    if (fileDescr == -1){
        if (errno == EACCES || errno == EPERM){
            fprintf(stdout,"Not having permissions to open the file.\n");
            actiondenied = 1;
        }else if (errno == ENOENT){
            fprintf(stdout,"The file you trying to open doesn't exist.\n");
            return fileDescr;
        }else{
            fprintf(stdout,"Unknown error, not permission related!\n");
            return fileDescr;
        }
    }
    
    SpyUserActivity(fileDescr, path, "1", (actiondenied == 1)? "1":"0");
    return fileDescr;
    
}


size_t fwrite(const void * ptr, size_t size, size_t nmemb, FILE *stream){
    int actiondenied;
    int MAXSIZE = 0xFFF;
    char proclnk[0xFFF];
    char filename[0xFFF];
    int fno;
    ssize_t r;
    
    printf("In our own fwrite\n");
    
    size_t (*original_fwrite)(const void *, size_t, size_t, FILE *);
    original_fwrite = dlsym(RTLD_NEXT, "fwrite");
    size_t sz = (*original_fwrite)(ptr, size, nmemb, stream);
    
    if (stream != NULL){
        fno = fileno(stream);
        sprintf(proclnk, "/proc/self/fd/%d", fno);
        r = readlink(proclnk, filename, MAXSIZE);
        if (r < 0)
        {
            fprintf(stdout,"failed to readlink\n");
            exit(1);
        }
        filename[r] = '\0';
    }
    char *filename1 = basename(filename);
    
    if (sz < size){
        if (errno == EACCES || errno == EPERM){
            fprintf(stdout,"Not having permissions to fwrite the file.\n");
            actiondenied = 1;
        }else if (errno == ENOENT){
            fprintf(stdout,"The file you trying to open doesn't exist.\n");
            return sz;
        }else{
            fprintf(stdout,"Unknown error, not permission related!\n");
            return sz;
        }
    }
    
    SpyUserActivity(fno, filename1, "0", (actiondenied == 1)? "1":"0");

    return sz;
    
}



ssize_t write(int fildes, const void *buf, size_t nbyte){
    int actiondenied;
    int MAXSIZE = 0xFFF;
    char proclnk[0xFFF];
    char filename[0xFFF];
    ssize_t r;
    
    size_t (*original_write)(int, const void *, size_t);
    original_write = dlsym(RTLD_NEXT, "write");
    size_t sz = (*original_write)(fildes, buf, nbyte);
    
    sprintf(proclnk, "/proc/self/fd/%d", fildes);
    r = readlink(proclnk, filename, MAXSIZE);
    if (r < 0)
    {
        fprintf(stderr,"failed to readlink\n");
        exit(1);
        
    }
    
    filename[r] = '\0';
    
    char *filename1 = basename(filename);
   
      if (sz == -1){
        if (errno == EACCES || errno == EPERM){
            printf("Not having permissions to fopen the file.\n");
            actiondenied = 1;
        }else if (errno == ENOENT){
            printf("The file you trying to open doesn't exist.\n");
            return sz;
        }else{
            printf("Unknown error, not permission related!\n");
            return sz;
        }
    }
    
    SpyUserActivity(fildes, filename1, "0", (actiondenied == 1)? "1":"0");
    return sz;
    
}
