#include <stdlib.h>
#include <stdio.h>

typedef struct RELAY_CHAINED_LIST_LINK
{
	RELAY_CHAINED_LIST_ITEM content;
	struct RELAY_CHAINED_LIST_LINK *nxt;
} 	RELAY_CHAINED_LIST_LINK;

typedef struct RELAY_CHAINED_LIST
{
	int max_id;
	RELAY_CHAINED_LIST_LINK *first;
}	RELAY_CHAINED_LIST

void RelayChaineListInit (RELAY_CHAINED_LIST* p, int id)
{
	max_id = 0;
	first = NULL:
}

int RelayChaineListDelete (RELAY_CHAINED_LIST* p, int id)
{
	RELAY_CHAINED_LIST_LINK* c = p->first;
	if (!c) {return -1;}
	if (c->id==id)		// the item we want to delete is at the first place
	{
		p->first = (*p)->nxt;
		free(*c);
		return 0;
	}
	while(c->nxt)		// it is in the list
	{
		if (c->nxt->id==id)
		{
			RELAY_CHAINED_LIST_LINK* tmp = c->nxt;
			c->nxt=c->nxt->nxt;
			free(tmp);
			return 0;
		}
		c = c->nxt;
	}
	return -1;
}


int RelayChaineListFind (RELAY_CHAINED_LIST* p, int id, RELAY_CHAINED_LIST_ITEM *item) 
{
	RELAY_CHAINED_LIST_LINK* c = p->first;
	while(c)
	{
		if (c->item.id==id) 
		{
			*item = &(c->item);
			return 0;
		}
		c = c->nxt;
	}
	return -1;
}


void RelayChaineListPush (RELAY_CHAINED_LIST *p, RELAY_CHAINED_LIST_ITEM *item)
{
	RELAY_CHAINED_LIST_LINK* el = malloc(sizeof(RELAY_CHAINED_LIST_LINK));

	el->id = p->max_id+1;
	p->max_ip++;
	el->id = link.id;
	el->nxt = p->first;
	p->first = el;

	item = &(el->item);
}

void RelayChaineListClear (RELAY_CHAINED_LIST *p)
{
	RELAY_CHAINED_LIST* c;
	RELAY_CHAINED_LIST* tmp;
	c = p->first;
	while(c != NULL)
	{
		tmp = c->nxt;
		free(c);
		c = tmp;
	}
}
