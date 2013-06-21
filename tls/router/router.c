#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include <string.h>
#include "server.c"
#include "client.c"
#include "chainedList.c"


void* maFonction(void* data);
  
int main()
{
    connectionList* test = NULL;
    Push(&test,1,2,3);
    Push(&test,2,12,56);
    Push(&test,3,5,6);
    int a;
    int b;
    Del(&test,2);
    int o = Find(&test,3,&a,&b);
    printf("-- %d %d %d --",o,a,b);

    int i;
    pthread_t thread;
    pthread_create(&thread, NULL, maFonction, NULL);
  
    // Affiche 50 fois 1
    for(i=0 ; i<50 ; i++)
        printf("1");
  
    // Attend la fin du thread créé
    pthread_join(thread, NULL);
     
    return 0;
}
  
  
void* maFonction(void* data)
{
    int i;
     
    // Affiche 50 fois 2
    for(i=0 ; i<50 ; i++)
        printf("2");
     
    return NULL;
}
