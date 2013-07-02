/* ################################################################################

						Chained List Implementation

			A Generic structure with several Items used in Porc

   ################################################################################*/

#include "chained_list.h"

//Initialisation of a Generic List
void ChainedListInit (CHAINED_LIST* p)
{
	p->index = 0;
	p->length = 0;
	p->first = NULL;
}

//Remove Element of id given in list
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

//Return the item of id given as argument
int ChainedListFind (CHAINED_LIST* p, int id, void **item) 
{
	CHAINED_LIST_LINK* c = p->first;
	while(c)
	{
		if (c->id==id) 
		{
			*item = c->item;
			return 0;
		}
		c = c->nxt;
	}
	return -1;
}

//Set the flag 'complete' of the item id to true. It can know be read with ChainListFind
int ChainedListComplete (CHAINED_LIST* p, int id) {
	CHAINED_LIST_LINK* c = p->first;
	while(c)
	{
		if (c->id==id) 
		{
			c->complete=1;
			return 0;
		}
		c = c->nxt;
	}
	return -1;
}

//Creates a new element at the top of list p
//It returns a pointer (**item) on the created item
int ChainedListNew (CHAINED_LIST *p, void **item, int item_size)
{
	CHAINED_LIST_LINK* el = malloc(sizeof(CHAINED_LIST_LINK));

	el->id = p->index;
	el->complete = 0;
	printf ("id = %d\n", el->id);
	el->item = malloc(item_size);
	printf ("item = %X\n", (unsigned int)(el->item));
	el->nxt = p->first;
	p->first = el;

	p->index++;
	p->length++;

	
	*item = el->item;

	printf ("ChainedListNew : new el %d at %d\n", el->id, (int)(el->item));
	
	return el->id;
}

//Next item in list
int ChainedListNext (CHAINED_LIST_LINK **p, void **item) {
	if ((*p)->nxt != NULL) {
		*p = (*p)->nxt;
		*item = &((*p)->item);
		return 0;
	}

	return -1;
}

//Clears the list
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
