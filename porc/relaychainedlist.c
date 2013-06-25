#include "relaychainedlist.h"


RELAY_CHAINED_LIST porc_sessions;



void RelayChainedListInit (RELAY_CHAINED_LIST* p)
{
	p->index = 0;
	p->length = 0;
	p->first = NULL;
}

int RelayChainedListRemove (RELAY_CHAINED_LIST* p, int id)
{
	RELAY_CHAINED_LIST_LINK* c = p->first;
	if (c == NULL) {
		return -1;
	}
	if (c->item.id==id)		// the item we want to delete is at the first place
	{
		p->first = p->first->nxt;
		p->length--;
		free(c);
		return 0;
	}
	while(c->nxt != NULL)		// it is in the list
	{
		if (c->nxt->item.id==id)
		{
			RELAY_CHAINED_LIST_LINK* tmp = c->nxt;
			c->nxt=c->nxt->nxt;
			p->length--;
			free(tmp);
			return 0;
		}
		c = c->nxt;
	}
	return -1;
}


int RelayChainedListFind (RELAY_CHAINED_LIST* p, int id, RELAY_CHAINED_LIST_ITEM **item) 
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


void RelayChainedListNew (RELAY_CHAINED_LIST *p, RELAY_CHAINED_LIST_ITEM **item)
{
	RELAY_CHAINED_LIST_LINK* el = malloc(sizeof(RELAY_CHAINED_LIST_LINK));

	el->item.id = p->index;
	el->nxt = p->first;
	p->first = el;

	p->index++;
	p->length++;

	*item = &(el->item);
}

void RelayChainedListClear (RELAY_CHAINED_LIST *p)
{
	RELAY_CHAINED_LIST_LINK* c;
	RELAY_CHAINED_LIST_LINK* tmp;
	c = p->first;
	while(c != NULL)
	{
		tmp = c->nxt;
		free(c);
		c = tmp;
	}
	p->index = 0;
	p->length = 0;
	p->first = NULL;
}
