#include <assert.h>
#include "service.h"

int main(void)
{
    assert(place_order("book") == 0);
    return 0;
}
