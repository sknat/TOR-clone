/*****************************************************************************
/
/			--LinkedList Library--
/		  Inspired by http://developpez.net
/			
*****************************************************************************/



#include <stdlib.h>
#include <stdio.h>

typedef struct _connectionList 
{
	int ip_in; 		// the next ip towards origin (next router point in the direction of the client)
	int ip_out;		// the next ip towards end (next router point in the direction of the end of the tunnel)
	int id;			// Connection id
	struct _connectionList *nxt;
} 	connectionList;


int Del(connectionList** p, int id)
{
        connectionList* c = *p;
	if (!c) {return 0;}
	if (c->id==id) // the item we want to delete is at the first place
	{
		connectionList* tmp = (*p)->nxt;
		free(*p);
		*p=tmp;
		return 1;
	}
	while(c->nxt) // it is in the list
        {
                if (c->nxt->id==id)
                {
			//connectionList* tmp = c->nxt;
                        c->nxt=c->nxt->nxt;
			//free(tmp);
			return 1;
                }
                c = c->nxt;
        }
        return 0;
}


int Find(connectionList** p, int id, int *pIp_in, int *pIp_out) 
{
	connectionList* c = *p;
	while(c)
	{
		if (c->id==id) 
		{
		        *pIp_in=c->ip_in;
		        *pIp_out=c->ip_out;
			return 1;
		}
		c = c->nxt;
	}
	return 0;
}


void Push(connectionList **p, int id, int ip_in, int ip_out)
{
        connectionList *el = malloc(sizeof(connectionList));
        if(!el) exit(EXIT_FAILURE); // allocation aborted
        el->ip_in = ip_in;
	el->ip_out = ip_out;
	el->id = id;
        el->nxt = *p;
        *p = el;
}

void Clear(connectionList **p)
{
        connectionList *tmp;
        while(*p)
          {
             tmp = (*p)->nxt;
             free(*p);
             *p = tmp;
          }
}
