#include "chainedlist.h"



void ChainedListInit (CHAINED_LIST* p)
{
	p->index = 0;
	p->length = 0;
	p->first = NULL;
}

int ChainedListRemove (CHAINED_LIST* p, int id)
{
	CHAINED_LIST_LINK* c = p->first;
	if (c == NULL) {
		return -1;
	}
	if (c->id==id)		// the item we want to delete is at the first place
	{
		p->first = p->first->nxt;
		p->length--;
		free(c->item);
		free(c);
		return 0;
	}
	while(c->nxt != NULL)		// it is in the list
	{
		if (c->nxt->id==id)
		{
			CHAINED_LIST_LINK* tmp = c->nxt;
			c->nxt=c->nxt->nxt;
			p->length--;
			free(tmp->item);
			free(tmp);
			return 0;
		}
		c = c->nxt;
	}
	return -1;
}


int ChainedListFind (CHAINED_LIST* p, int id, void **item) 
{
	CHAINED_LIST_LINK* c = p->first;
	while(c)
	{
		if (c->id==id) 
		{
			*item = &(c->item);
			return 0;
		}
		c = c->nxt;
	}
	return -1;
}


int ChainedListNew (CHAINED_LIST *p, void **item, int item_size)
{
	CHAINED_LIST_LINK* el = malloc(sizeof(CHAINED_LIST_LINK));

	el->id = p->index;
	el->item = malloc(item_size);
	el->nxt = p->first;
	p->first = el;

	p->index++;
	p->length++;

	*item = &(el->item);
	
	return el->id;
}

void ChainedListClear (CHAINED_LIST *p)
{
	CHAINED_LIST_LINK* c;
	CHAINED_LIST_LINK* tmp;
	c = p->first;
	while(c != NULL)
	{
		tmp = c->nxt;
		free(c);
		free(c->item);
		c = tmp;
	}
	p->index = 0;
	p->length = 0;
	p->first = NULL;
}
