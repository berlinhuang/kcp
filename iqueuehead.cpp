//
// Created by root on 18-4-11.
//
#include "ikcp.h"
#include <stdlib.h>
struct SEG
{
    struct IQUEUEHEAD node;
    int id;
};

struct MYPCB
{
    struct IQUEUEHEAD snd_queue;
};

typedef struct MYPCB mypcb;

int main()
{
    mypcb *mypb = (mypcb*)malloc(sizeof(struct MYPCB));
    iqueue_init(&mypb->snd_queue);
    for(int i = 0;i<10;i++)
    {
        SEG *myseg = (struct SEG*)malloc(sizeof(struct SEG));
        myseg->id = i;
        iqueue_init(&myseg->node);
        iqueue_add_tail(&myseg->node, &mypb->snd_queue);
    }
    return 0;
}