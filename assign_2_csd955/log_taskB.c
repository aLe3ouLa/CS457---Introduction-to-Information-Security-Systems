#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct node{ 
    char *userID;
    char *filename;
    char *date;
    char *time;
    char *open;
    char *action_denied;
    char *hash;
    
    struct node *next;
};

struct node_users_activity{
    char *userID;
    int count;
    struct files_user_accessed *head;
    
    struct node_users_activity *next;
};

struct files_user_accessed{
    char *filename;
    struct files_user_accessed *next;
    
};

struct node *UserSinglyList;
struct node_users_activity *UserActivitySinglyList;


void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n log logfile_path mode [filename]"
	);
	printf(
	    "\n"
	    "Mode:\n"
	    " 1    Print users trying to access files without permission\n"
	    " 2 filename For a given file print users that have access to that file \n"
	    " 3    Print users that have unsuccessfully tried to access more than 10 files in less than 24h\n"
	);
	exit(EXIT_FAILURE);
}

void insertUser(struct node **userList, char *userID, char *filename, char *date, char *time, char *open, char * action_denied, char * hash){
    struct node *newNode = NULL;
    struct node *prev = *userList ;

    newNode = malloc(sizeof(struct node));
    if (newNode == NULL){
        fprintf(stderr, "Failed to allocate memory");
        exit(0);
    }
    newNode->userID = malloc(strlen(userID) *sizeof(char));
    strcpy(newNode->userID,userID);
    
    newNode->filename = malloc(strlen(filename) *sizeof(char));
    strcpy(newNode->filename , filename);
    
    newNode->date = malloc(strlen(date) *sizeof(char));
    strcpy(newNode->date , date);
    
    newNode->time = malloc(strlen(time) *sizeof(char));
    strcpy(newNode->time , time);
    
    newNode->open = malloc(strlen(open) *sizeof(char));
    strcpy(newNode->open, open);
    
    newNode->action_denied = malloc(strlen(action_denied) *sizeof(char));
    strcpy(newNode->action_denied , action_denied);
    
    newNode->hash = malloc(strlen(hash) *sizeof(char));
    strcpy(newNode->hash , hash);
    
    newNode->next =  *userList;
    *userList = newNode;
}

void insertUserAct(struct node_users_activity **userActList, char *userID){
    struct node_users_activity *newNode = NULL;
    
    newNode = malloc(sizeof(struct node_users_activity));
    if (newNode == NULL){
        fprintf(stderr, "Failed to allocate memory");
        exit(0);
    }
    newNode->userID = malloc(strlen(userID) *sizeof(char));
    strcpy(newNode->userID,userID);

    newNode->head = NULL;
    newNode->count = 1;
    
    newNode->next =  *userActList;
    *userActList = newNode;
}

void insertFile(struct files_user_accessed **fileList, char*filename){
    struct files_user_accessed *newNode = NULL;
    
    newNode = malloc(sizeof(struct files_user_accessed));
    if (newNode == NULL){
        fprintf(stderr, "Failed to allocate memory");
        exit(0);
    }
    newNode->filename = malloc(strlen(filename) *sizeof(char));
    strcpy(newNode->filename,filename);
    
    newNode->next =  *fileList;
    *fileList = newNode;
}

void printUser(struct node * userList){
    while (userList != NULL){
        printf("Print!:%s\t%s\t%s\t%s\t%s\t%s\t%s\n",userList->userID, userList->filename, userList->date,userList->time,userList->open , userList->action_denied,userList->hash);
        userList = userList->next;
    }
}

void findUsersWithoutPermission(struct node *userList){
    printf("Task B1 output: \n");
    while (userList != NULL){
       // printf("%s", userList->action_denied);
        if (!strcmp(userList->action_denied, "1")){
                printf("%s\n", userList->userID);
        }
        userList = userList->next;
    }
}

void findUsersByFIleName(struct node *userList, char *filename){
    printf("Task B2 output: \n");
    
    while (userList != NULL){
        if (!strcmp(userList->filename, filename)){
            printf("%s\t", userList->userID);
            if (!strcmp(userList->open, "1") && !strcmp(userList->action_denied, "0")){
                /*User open the file for reading and the access is not denied : The file isn't modified*/
                printf("A\n");
            }else{
                if (userList->next!= NULL){
                    if (!strcmp(userList->hash, "(null)")){
                        /* Hash == null, we want to write and the access is not denied*/
                        if (!strcmp(userList->open, "0") && !strcmp(userList->action_denied, "0")){
                           printf("M\n");
                        }
                    }else if (!strcmp(userList->hash, userList->next->hash)){
                        printf("A\n");
                    }else{
                        printf("M\n");
                    }
                }else{
                    if (!strcmp(userList->hash, "(null)")){
                        /* Hash == null, we want to write and the access is not denied*/
                        if (!strcmp(userList->open, "0") && !strcmp(userList->action_denied, "0")){
                           printf("M\n");
                        }
                    }else{
                        if (!strcmp(userList->open, "1") && !strcmp(userList->action_denied, "0")){
                            printf("A\n");
                        }else {
                        
                            printf("M\n");
                        }
                    }
                }
            }
        }
        userList = userList->next;
    }
}

void findUsersInLast24Hours(struct node *userList, struct node_users_activity *userActList){
    
    struct node *temp = userList;
    
    struct node_users_activity *found;
    char currentdate[20];
    time_t t = time(NULL);
    time_t tm;
    struct tm * tm_info = localtime(&t);
    struct tm tm1, tm2; // intermediate datastructes 
    time_t t1, t2; 
    
    printf("Task B3 output: \n");
    
    strftime(currentdate, 20, "%Y-%m-%d %H:%M:%S\n", tm_info);
    
  //  printf("%s\n",currentdate);

    while (temp != NULL){
        struct node_users_activity *tempActivity = userActList;
        char date[20]; 
        strcpy(date, temp->date);
        strcat(date, " ");
        strcat(date, temp->time);
        
       // printf("\n%s\n",date);
        
        //(1) convert `String to tm`:  (note: %T same as %H:%M:%S)  
        if(strptime(date, "%Y-%m-%d %T", &tm1) == NULL)
            printf("\nstrptime failed-1\n");          
        if(strptime(currentdate, "%Y-%m-%d %T", &tm2) == NULL)
            printf("\nstrptime failed-2\n");
        
        //(2) convert `tm to time_t`:    
        t1 = mktime(&tm1);   
        t2 = mktime(&tm2);  
        //(3) Convert Seconds into hours
        double hours = difftime(t2, t1)/60/60;
        //printf("%lf\n", hours);
        
        /*find if an activity for userID exists*/
        while(tempActivity != NULL){
            //printf("tempActivity->userID:\"%s\", temp->userID:\"%s\"\n",tempActivity->userID, temp->userID);
            if (!strcmp(tempActivity->userID, temp->userID)){
                found = tempActivity;
                break;
            }
            tempActivity = tempActivity->next;
        }
        
        if(tempActivity == NULL){
           // printf("not users in list %s\t%s\n",temp->userID, temp->action_denied);
            if (!strcmp(temp->action_denied, "1")){
                if(hours <= 24.0 && hours >=0){
                       // printf("%lf\t", hours);
                        insertUserAct(&userActList, temp->userID);
                        insertFile(&(userActList->head), temp->filename);
                     //   printf("%s illegal %d\n",temp->userID,userActList->count);
                }
            }
        }else{
            if (found == NULL){
                /*Not found log for that user*/
                if (!strcmp(temp->action_denied, "1")){
                    if(hours <= 24.0 && hours >=0){
                        //printf("%lf\t", hours);
                        insertUserAct(&userActList, temp->userID);
                        insertFile(&(userActList->head), temp->filename);
                     //   printf("%s illegal %d\n",temp->userID,userActList->count);
                    }
                }
            }
            else{
            struct files_user_accessed * tempFile = (userActList->head);
            int fileFound = 0;
               if (!strcmp(temp->action_denied, "1")){
                   if(hours <= 24.0 && hours >=0){
                       //  printf("%lf\t", hours);
                         while(tempFile != NULL){
                             if(!strcmp(temp->filename, tempFile->filename)){
                                 fileFound = 1;
                                 break;
                             }
                             tempFile =  tempFile->next;
                         }
                         
                         if (fileFound == 0)
                            found->count++;
                   }
                } 
               // printf("%s illegal %d\n",temp->userID,found->count);
            }
            
            
        }

        temp = temp->next;
    }
    
    while (userActList != NULL){
        if (userActList->count > 10){
            printf("%s\n", userActList->userID);
        }
        userActList = userActList->next;
    }
    
}

int main (int argc, char *argv[]){
    int i = 0;
    char *logName;
    char *functionNum;
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    
    if(argc != 3 && argc!=4)
        usage();
    
    UserSinglyList = NULL;
    UserActivitySinglyList= NULL;
    logName = argv[1];
    functionNum = argv[2];
    
    fp = fopen(logName, "r");
     
    while((read = getline(&line, &len, fp))!=-1){
        char *str[7];
        char *pch;
        pch = strtok(line, " ");
        int j = 0;
        while(pch!=NULL){
                str[j] = pch;
                pch = strtok(NULL, " ");
                j++;
        }
        
        insertUser(&UserSinglyList,str[0],str[1],str[2],str[3],str[4],str[5],str[6]);
        
    }
    
    if (!strcmp(functionNum, "1")){
      findUsersWithoutPermission(UserSinglyList);
    }else if (!strcmp(functionNum, "2")){
        char *fileName;
        fileName = argv[3];
        findUsersByFIleName(UserSinglyList, fileName);
    }else if (!strcmp(functionNum, "3")){
        findUsersInLast24Hours(UserSinglyList,UserActivitySinglyList);
    }else{
        printf("Wrong!\n");
    }
}