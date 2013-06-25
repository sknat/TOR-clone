#include "clientchainedlist.h"


CLIENT_CHAINED_LIST porc_sessions;



void ClientChainedListInit (CLIENT_CHAINED_LIST* p)
{
	p->index = 0;
	p->length = 0;
	p->first = NULL;
}

int ClientChainedListRemove (CLIENT_CHAINED_LIST* p, int id)
{
	CLIENT_CHAINED_LIST_LINK* c = p->first;
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
			CLIENT_CHAINED_LIST_LINK* tmp = c->nxt;
			c->nxt=c->nxt->nxt;
			p->length--;
			free(tmp);
			return 0;
		}
		c = c->nxt;
	}
	return -1;
}


int ClientChainedListFind (CLIENT_CHAINED_LIST* p, int id, CLIENT_CHAINED_LIST_ITEM **item) 
{
	CLIENT_CHAINED_LIST_LINK* c = p->first;
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


void ClientChainedListNew (CLIENT_CHAINED_LIST *p, CLIENT_CHAINED_LIST_ITEM **item)
{
	CLIENT_CHAINED_LIST_LINK* el = malloc(sizeof(CLIENT_CHAINED_LIST_LINK));

	el->item.id = p->index;
	el->nxt = p->first;
	p->first = el;

	p->index++;
	p->length++;

	*item = &(el->item);
}

void ClientChainedListClear (CLIENT_CHAINED_LIST *p)
{
	CLIENT_CHAINED_LIST_LINK* c;
	CLIENT_CHAINED_LIST_LINK* tmp;
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
