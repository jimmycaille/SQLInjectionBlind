#ifndef ATTACK_HEADER_FILE
#define ATTACK_HEADER_FILE

//used for text response handling
struct string {
  char *ptr;
  size_t len;
};

//prototypes
void cleanup();
void printParams(char* usr);
void init_string(struct string*);
size_t writefunc(void*, size_t, size_t, struct string*);
int doRequest(char* params);

#endif